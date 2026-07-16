//go:build windows

package misc

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// detectWindowsVersion returns the OS version the way the real Codex UA does.
//
// The openai/codex UA is built by os_info, which on Windows calls the NT API
// RtlGetVersion and formats the result as "major.minor.build" (e.g.
// "10.0.26200"). We mirror that exactly by calling RtlGetVersion ourselves via
// golang.org/x/sys/windows rather than reading the registry, so the forged UA's
// OS segment matches what Codex itself would emit. Windows 10 and 11 both report
// major version 10 here (Win 11 is only distinguished by a build >= 22000, which
// os_info uses for edition naming but not for the UA version string).
//
// RtlGetVersion is documented to always succeed, so this does not fail in
// practice; it returns "" only defensively if the build number is somehow zero.
func detectWindowsVersion() string {
	info := windows.RtlGetVersion()
	if info == nil || info.BuildNumber == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(info.MajorVersion), 10) + "." +
		strconv.FormatUint(uint64(info.MinorVersion), 10) + "." +
		strconv.FormatUint(uint64(info.BuildNumber), 10)
}
