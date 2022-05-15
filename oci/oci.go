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
	maxDeviceNumberMinor = 1<<20 - 1
	maxDeviceNumberMajor = 1<<12 - 1
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

func verifyDeviceCgroupType(dType, dNumbers, dAccess string) error {
	if dType != "a" && dType != "b" && dType != "c" {
		return fmt.Errorf("block device %s is not allowed, only 'a', 'b' and 'c' are allowed", dType)
	}

	if dType == "a" {
		if _, _, err := parseDeviceCgroupNumbers(dAccess); err != nil {
			return err
		}

		a, err := parseDeviceCgroupAccess(dAccess)
		if err != nil {
			return err
		}

		if dNumbers != "*:*" {
			return fmt.Errorf("invalid device numbers: %s", dNumbers)
		}

		if *a != (dAccessRWM) {
			return fmt.Errorf("invalid device access: %s for type %s", a.String(), dType)
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
			return nil, nil, newDevCgroupNumbersError(err, maxDeviceNumberMinor)
		}

		if value > maxDeviceNumberMinor || value < 0 {
			return nil, nil, fmt.Errorf("%d is out of range, it should be between %d and %d", value, 0, maxDeviceNumberMinor)
		}

		minor = value
	}

	if numbersParts[1] != "*" {
		value, err := strconv.ParseInt(numbersParts[1], 10, 64)
		if err != nil {
			return nil, nil, newDevCgroupNumbersError(err, maxDeviceNumberMajor)
		}

		if value > maxDeviceNumberMajor || value < 0 {
			return nil, nil, fmt.Errorf("%d is out of range, it should be between %d and %d", value, 0, maxDeviceNumberMajor)
		}

		major = value
	}

	return &major, &minor, nil
}

func parseDeviceCgroupAccess(access string) (*dAccess, error) {
	if access == "" {
		return nil, errors.New("access should not be empty")
	}

	var deviceAccess dAccess

	if len(access) > 3 {
		return nil, errors.New("access should not have more than 3 components")
	}

	for _, c := range access {
		if c != 'r' && c != 'w' && c != 'm' {
			return nil, fmt.Errorf("access %c is not allowed, only 'r', 'w' and 'm' are allowed", c)
		}

		if c == 'r' {
			if deviceAccess.read {
				return nil, fmt.Errorf("%c access should not appear more than one", c)
			}

			deviceAccess.read = true
		}

		if c == 'w' {
			if deviceAccess.write {
				return nil, fmt.Errorf("%c access should not appear more than one", c)
			}

			deviceAccess.write = true
		}

		if c == 'm' {
			if deviceAccess.mknod {
				return nil, fmt.Errorf("%c access should not appear more than one", c)
			}

			deviceAccess.mknod = true
		}
	}

	return &deviceAccess, nil
}

var dAccessRWM = dAccess{read: true, write: true, mknod: true}

type dAccess struct {
	read, write, mknod bool
}

func (d dAccess) String() string {
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
