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

const (
	msgEmptyAccess          = "access should not be empty"
	msgRepeatedAccess       = "%c access should not appear more than one"
	msgInvalidAccess        = "access %c is not allowed, only 'r', 'w' and 'm' are allowed"
	msgLongAccess           = "access should not have more than 3 components"
	msgNumbersOutOfRange    = "%d is out of range, it should be between %d and %d"
	msgInvalidNumbersFormat = "%s is does not have a valid format for device numbers"
	msgInvalidDevType       = "block device %s is not allowed, only 'a', 'b' and 'c' are allowed"
	msgInvalidRuleFormat    = "rule is not constituted of type, numbers and access"
)

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
	devTypeAll   = "a"
	devTypeBlock = "b"
	devTypeChar  = "c"

	devNumbersAll = "*:*"
	devNumberAll  = "*"
	devNumbersSep = ":"

	maxMinor = 1<<20 - 1
	maxMajor = 1<<12 - 1

	devAccessAll = "rwm"
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
		if rule != devTypeAll {
			return specs.LinuxDeviceCgroup{}, fmt.Errorf(msgInvalidDevType, rule)
		}

		var (
			majorAll = int64(-1)
			minorAll = int64(-1)
		)

		return specs.LinuxDeviceCgroup{
			Allow:  true,
			Access: "rwm",
			Major:  &majorAll,
			Minor:  &minorAll,
		}, nil
	}

	if len(ruleParts) != 3 {
		return specs.LinuxDeviceCgroup{}, fmt.Errorf(msgInvalidRuleFormat)
	}

	var (
		devType    = ruleParts[0]
		devNumbers = ruleParts[1]
		devAccess  = ruleParts[2]
	)

	dType, err := parseDeviceCgroupType(devType, devNumbers, devAccess)
	if err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	major, minor, err := parseDeviceCgroupNumbers(devNumbers)
	if err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	dAccess, err := parseDeviceCgroupAccess(devAccess)
	if err != nil {
		return specs.LinuxDeviceCgroup{}, err
	}

	return specs.LinuxDeviceCgroup{
		Allow:  true,
		Type:   dType,
		Major:  major,
		Minor:  minor,
		Access: dAccess.String(),
	}, nil
}

func parseDeviceCgroupType(d, devNumbers, devA string) (string, error) {
	if d != devTypeAll && d != devTypeBlock && d != devTypeChar {
		return "", fmt.Errorf(msgInvalidDevType, d)
	}

	if d == devTypeAll {
		if _, _, err := parseDeviceCgroupNumbers(devA); err != nil {
			return "", err
		}

		a, err := parseDeviceCgroupAccess(devA)
		if err != nil {
			return "", err
		}

		if devNumbers != devNumbersAll {
			return "", fmt.Errorf("invalid device numbers: %s", devNumbers)
		}

		if a != (deviceAccess{read: true, write: true, mknod: true}) {
			return "", fmt.Errorf("invalid device access: %s", a.String())
		}
	}

	return d, nil
}

func parseDeviceCgroupNumbers(numbers string) (major *int64, minor *int64, err error) {
	numbersParts := strings.Split(numbers, devNumbersSep)

	if len(numbersParts) != 2 {
		return nil, nil, fmt.Errorf(msgInvalidNumbersFormat, numbers)
	}

	majorPtr := int64(-1)
	minorPtr := int64(-1)

	if numbersParts[0] != devNumberAll {
		minor, err := strconv.ParseInt(numbersParts[0], 10, 64)
		if err != nil {
			return nil, nil, newDevCgroupNumbersError(err, maxMinor)
		}

		if minor > maxMinor || minor < 0 {
			return nil, nil, fmt.Errorf(msgNumbersOutOfRange, minor, 0, maxMinor)
		}

		minorPtr = minor
	}

	if numbersParts[1] != devNumberAll {
		major, err := strconv.ParseInt(numbersParts[1], 10, 64)
		if err != nil {
			return nil, nil, newDevCgroupNumbersError(err, maxMajor)
		}

		if major > maxMajor || major < 0 {
			return nil, nil, fmt.Errorf(msgNumbersOutOfRange, major, 0, maxMajor)
		}

		majorPtr = major
	}

	return &majorPtr, &minorPtr, nil
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
		return deviceAccess{}, errors.New(msgEmptyAccess)
	}

	var dA deviceAccess

	if len(access) > 3 {
		return deviceAccess{}, errors.New(msgLongAccess)
	}

	for _, c := range access {
		if c != 'r' && c != 'w' && c != 'm' {
			return deviceAccess{}, fmt.Errorf(msgInvalidAccess, c)
		}

		if c == 'r' {
			if dA.read {
				return deviceAccess{}, fmt.Errorf(msgInvalidAccess, c)
			}

			dA.read = true
		}

		if c == 'w' {
			if dA.write {
				return deviceAccess{}, fmt.Errorf(msgInvalidAccess, c)
			}

			dA.write = true
		}

		if c == 'm' {
			if dA.mknod {
				return deviceAccess{}, fmt.Errorf(msgInvalidAccess, c)
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
