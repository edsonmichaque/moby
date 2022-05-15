package oci // import "github.com/docker/docker/oci"

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TODO verify if this regex is correct for "a" (all); the docs (https://github.com/torvalds/linux/blob/v5.10/Documentation/admin-guide/cgroup-v1/devices.rst) describe:
//      "'all' means it applies to all types and all major and minor numbers", and shows an example
//      that *only* passes `a` as value: `echo a > /sys/fs/cgroup/1/devices.allow, which would be
//      the "implicit" equivalent of "a *:* rwm". Source-code also looks to confirm this, and returns
//      early for "a" (all); https://github.com/torvalds/linux/blob/v5.10/security/device_cgroup.c#L614-L642
//nolint: gosimple
var deviceCgroupRuleRegex = regexp.MustCompile("^([acb]) ([0-9]+|\\*):([0-9]+|\\*) ([rwm]{1,3})$")

// SetCapabilities sets the provided capabilities on the spec
// All capabilities are added if privileged is true.
func SetCapabilities(s *specs.Spec, caplist []string) error {
	// setUser has already been executed here
	if s.Process.User.UID == 0 {
		s.Process.Capabilities = &specs.LinuxCapabilities{
			Effective: caplist,
			Bounding:  caplist,
			Permitted: caplist,
		}
	} else {
		// Do not set Effective and Permitted capabilities for non-root users,
		// to match what execve does.
		s.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding: caplist,
		}
	}
	return nil
}

// AppendDevicePermissionsFromCgroupRules takes rules for the devices cgroup to append to the default set
func AppendDevicePermissionsFromCgroupRules(devPermissions []specs.LinuxDeviceCgroup, rules []string) ([]specs.LinuxDeviceCgroup, error) {
	for _, deviceCgroupRule := range rules {
		dPermission, err := ParseDeviceCgroupRule(deviceCgroupRule)
		if err != nil {
			return nil, err
		}

		devPermissions = append(devPermissions, dPermission)
	}

	return devPermissions, nil
}

const (
	maxMinor = 1<<20 - 1
	maxMajor = 1<<12 - 1
)

func VerifyDeviceCgroupRule(rule string) error {
	if _, err := ParseDeviceCgroupRule(rule); err != nil {
		return err
	}

	return nil
}

func ParseDeviceCgroupRule(rule string) (specs.LinuxDeviceCgroup, error) {
	ruleParts := strings.Split(rule, " ")

	if len(ruleParts) == 1 {
		if rule != "a" {
			return specs.LinuxDeviceCgroup{}, fmt.Errorf("block device %s is not allowed, only 'a', 'b' and 'c' are allowed", rule)
		}

		major := int64(-1)
		minor := int64(-1)

		return specs.LinuxDeviceCgroup{
			Allow:  true,
			Access: "rwm",
			Major:  &major,
			Minor:  &minor,
		}, nil
	}

	if len(ruleParts) != 3 {
		return specs.LinuxDeviceCgroup{}, fmt.Errorf("rule is not constituted of type, numbers and access")
	}

	if err := verifyDeviceCgroupType(ruleParts[0], ruleParts[1], ruleParts[2]); err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	major, minor, err := parseDeviceCgroupNumbers(ruleParts[1])
	if err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	dAccess, err := parseDeviceCgroupAccess(ruleParts[2])
	if err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	return specs.LinuxDeviceCgroup{
		Allow:  true,
		Type:   ruleParts[0],
		Major:  major,
		Minor:  minor,
		Access: dAccess.String(),
	}, nil
}

func verifyDeviceCgroupType(d, devNumbers, devA string) error {
	if d != "a" && d != "b" && d != "c" {
		return fmt.Errorf("block device %s is not allowed, only 'a', 'b' and 'c' are allowed", d)
	}

	if d == "a" {
		if _, _, err := parseDeviceCgroupNumbers(devA); err != nil {
			return err
		}

		a, err := parseDeviceCgroupAccess(devA)
		if err != nil {
			return err
		}

		if devNumbers != "*:*" {
			return fmt.Errorf("invalid device numbers: %s", devNumbers)
		}

		if a != (deviceAccess{read: true, write: true, mknod: true}) {
			return fmt.Errorf("invalid device access: %s", a.String())
		}
	}

	return nil
}

func parseDeviceCgroupNumbers(numbers string) (*int64, *int64, error) {
	numbersParts := strings.Split(numbers, ":")

	if len(numbersParts) != 2 {
		return nil, nil, fmt.Errorf("%s does not have a valid format for an integer", numbers)
	}

	major := int64(-1)
	minor := int64(-1)

	if numbersParts[0] != "*" {
		value, err := strconv.ParseInt(numbersParts[0], 10, 64)
		if err != nil {
			return nil, nil, newDevCgroupNumbersError(err, maxMinor)
		}

		if value > maxMinor || value < 0 {
			return nil, nil, fmt.Errorf("%d is out of range, it should be between %d and %d", value, 0, maxMinor)
		}

		minor = value
	}

	if numbersParts[1] != "*" {
		value, err := strconv.ParseInt(numbersParts[1], 10, 64)
		if err != nil {
			return nil, nil, newDevCgroupNumbersError(err, maxMajor)
		}

		if value > maxMajor || value < 0 {
			return nil, nil, fmt.Errorf("%d is out of range, it should be between %d and %d", value, 0, maxMajor)
		}

		major = value
	}

	return &major, &minor, nil
}

type deviceAccess struct {
	read, write, mknod bool
}

func (d deviceAccess) String() string {
	var b strings.Builder

	if d.read {
		b.WriteRune('r')
	}

	if d.write {
		b.WriteRune('w')
	}

	if d.mknod {
		b.WriteRune('m')
	}

	return b.String()
}

func parseDeviceCgroupAccess(access string) (deviceAccess, error) {
	if access == "" {
		return deviceAccess{}, errors.New("access should not be empty")
	}

	var dA deviceAccess

	if len(access) > 3 {
		return deviceAccess{}, errors.New("access should not have more than 3 components")
	}

	for _, c := range access {
		if c != 'r' && c != 'w' && c != 'm' {
			return deviceAccess{}, fmt.Errorf("access %c is not allowed, only 'r', 'w' and 'm' are allowed", c)
		}

		if c == 'r' {
			if dA.read {
				return deviceAccess{}, fmt.Errorf("%c access should not appear more than one", c)
			}

			dA.read = true
		}

		if c == 'w' {
			if dA.write {
				return deviceAccess{}, fmt.Errorf("%c access should not appear more than one", c)
			}

			dA.write = true
		}

		if c == 'm' {
			if dA.mknod {
				return deviceAccess{}, fmt.Errorf("%c access should not appear more than one", c)
			}

			dA.mknod = true
		}
	}

	return dA, nil
}

func newDevCgroupNumbersError(err error, max int) error {
	if numErr, ok := err.(*strconv.NumError); ok {
		if numErr.Err == strconv.ErrSyntax {
			return fmt.Errorf("%s does not have a valid format for an integer", numErr.Num)
		}

		if numErr.Err == strconv.ErrRange {
			return fmt.Errorf("%s should be between %d and %d", numErr.Num, 0, max)
		}
	}

	return err
}
