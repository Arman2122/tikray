package adapters

import (
	"errors"
	"io"
	"strings"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// BuildUninstaller shares the tested binding removal, emergency detach and
// service observation logic without executing a script from the router.
func BuildUninstaller(dst io.Writer) error {
	source := func(name string) (string, error) {
		b, e := routerosfiles.Sources.ReadFile(name)
		if e != nil {
			return "", errors.New("installer: missing uninstall source")
		}
		return string(b), nil
	}
	between := func(name, start, end string) (string, error) {
		s, e := source(name)
		if e != nil {
			return "", e
		}
		_, body, ok := strings.Cut(s, start)
		part, _, valid := strings.Cut(body, end)
		if !ok || !valid {
			return "", errors.New("installer: invalid uninstall helper")
		}
		return part, nil
	}
	s, e := source("uninstall.rsc")
	if e != nil {
		return e
	}
	for _, f := range []struct{ key, file string }{{"RESTORE_SERVICE", "uninstall-service.rsc"}, {"REFERENCES", "uninstall-references.rsc"}, {"CLEANUP_DATA", "uninstall-data.rsc"}, {"INSTALL_LOCK", "install-lock.rsc"}} {
		part, err := source(f.file)
		if err != nil {
			return err
		}
		token := "# @TIKRAY_" + f.key + "@"
		if strings.Count(s, token) != 1 {
			return errors.New("installer: invalid uninstall template")
		}
		s = strings.Replace(s, token, part, 1)
	}
	bind, e := between("uninstall-bindings.rsc", "# BEGIN BINDING REMOVAL HELPER\n", "# END BINDING REMOVAL HELPER")
	if e != nil {
		return e
	}
	cert, e := between("certificate.rsc", "            # BEGIN API SERVICE READ\n", "            # END API SERVICE READ")
	if e != nil {
		return e
	}
	em, e := source("emergency-off.rsc")
	if e != nil {
		return e
	}
	detach, _, e := emergencySource(em)
	if e != nil {
		return e
	}
	const inspect = `$entries "inspect" $runnerIP`
	if strings.Count(detach, inspect) != 1 {
		return errors.New("installer: invalid emergency inspection source")
	}
	detach = strings.Replace(detach, inspect, inspect+`
            :if ($1 = "inspect") do={ :return true }`, 1)
	for _, p := range []struct{ key, body string }{{"BINDING_REMOVAL", bind}, {"SERVICE_READ", cert}, {"DETACH", ":local detach do={" + detach + "\n:return true\n}"}, {"SEALED", ":set packaged true"}} {
		key := "# @TIKRAY_" + p.key + "@"
		if strings.Count(s, key) != 1 {
			return errors.New("installer: invalid uninstall template")
		}
		s = strings.Replace(s, key, p.body, 1)
	}
	if strings.Contains(s, "# @TIKRAY_") {
		return errors.New("installer: unresolved uninstall source")
	}
	_, e = io.WriteString(dst, s)
	return e
}
