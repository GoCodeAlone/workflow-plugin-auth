package agentidentity

import "strings"

// Query targets remain finite exact entries in both the current grant and the
// host's tenant declaration. This syntax bound prevents encoded/duplicate
// aliases; it does not grant every query on an otherwise allowed path.
func previewTarget(target string) bool {
	pathname, query, queried := strings.Cut(target, "?")
	return len(target) <= 2048 && previewPath(pathname) && (!queried || canonicalPreviewQuery(query))
}

func previewResourceTarget(r Resource) (string, bool) {
	if !previewPath(r.Path) {
		return "", false
	}
	target := r.Path
	if r.Query != "" {
		target += "?" + r.Query
	}
	return target, previewTarget(target)
}

func canonicalPreviewQuery(query string) bool {
	if query == "" || len(query) > 512 {
		return false
	}
	pairs := strings.Split(query, "&")
	if len(pairs) > 8 {
		return false
	}
	previous := ""
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found || !previewQueryAtom(key, 64) || !previewQueryAtom(value, 128) || key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func previewQueryAtom(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
