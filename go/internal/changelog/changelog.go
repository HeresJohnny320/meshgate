// Package changelog embeds CHANGELOG.md so every node and the app can show
// the changes of the version they run, even offline. Lines start with "+"
// (added), "-" (removed) or "~" (changed or fixed); "## " starts a version.
package changelog

import _ "embed"

//go:embed CHANGELOG.md
var Text string
