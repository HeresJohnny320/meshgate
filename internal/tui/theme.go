package tui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Styles follow the iptable-UI look (github.com/HeresJohnny320/iptable-UI):
// a green brand bar, rounded panels, colored values and key badges.
// applyTheme sets every style at once.
var (
	brandStyle, sectionStyle, mutedStyle, labelStyle, selectedStyle lipgloss.Style
	publicStyle, addressStyle, portStyle, protocolStyle             lipgloss.Style
	enabledStyle, disabledStyle, keyStyle, messageStyle             lipgloss.Style
	valueStyle, focusedStyle, warnStyle, errStyle                   lipgloss.Style
	accentBorder, quietBorder, selectedBorder                       lipgloss.TerminalColor
)

type tuiTheme struct {
	name, label                                        string
	plain                                              bool
	brandFG, brandBG, section, muted, label_, selected string
	public, address, port, protocol, enabled, disabled string
	keyFG, keyBG, message, messageBorder               string
	accent, quiet, selectedBorder, value, focused      string
	warn, err                                          string
}

// tuiThemes are offered in this order; the first is the default.
var tuiThemes = []tuiTheme{
	{name: "classic", label: "Classic",
		brandFG: "#F2F7F3", brandBG: "#176B4B", section: "#75D6A3", muted: "#8B9A91", label_: "#96A79C", selected: "#F5F8F5",
		public: "#E5B85C", address: "#61C7D4", port: "#81D69F", protocol: "#C5A7EF", enabled: "#66D494", disabled: "#D9A36A",
		keyFG: "#12241A", keyBG: "#80D6A5", message: "#F0D28A", messageBorder: "#D9A64F",
		accent: "#3B7557", quiet: "#394940", selectedBorder: "#58B981", value: "#DDE7DF", focused: "#F2C96D",
		warn: "#F0D28A", err: "#F07A6A"},
	{name: "readable", label: "Readable",
		brandFG: "#000000", brandBG: "#FFD75F", section: "#FFFFFF", muted: "#D0D0D0", label_: "#E4E4E4", selected: "#FFFFFF",
		public: "#FFD75F", address: "#5FD7FF", port: "#87FF87", protocol: "#FF87FF", enabled: "#5FFF5F", disabled: "#FF8700",
		keyFG: "#000000", keyBG: "#FFFFFF", message: "#FFFFFF", messageBorder: "#FFD75F",
		accent: "#FFFFFF", quiet: "#8A8A8A", selectedBorder: "#FFD75F", value: "#FFFFFF", focused: "#FFD75F",
		warn: "#FFD75F", err: "#FF5F5F"},
	{name: "light", label: "Light terminal",
		brandFG: "#FFFFFF", brandBG: "#176B4B", section: "#0E5A3A", muted: "#4E5D55", label_: "#3D4A43", selected: "#000000",
		public: "#8A5A00", address: "#005F87", port: "#1F6B3A", protocol: "#6B2FA0", enabled: "#1E7A44", disabled: "#A0461C",
		keyFG: "#FFFFFF", keyBG: "#176B4B", message: "#5A3C00", messageBorder: "#B07A1A",
		accent: "#176B4B", quiet: "#9AA59E", selectedBorder: "#0E5A3A", value: "#1A1A1A", focused: "#8A3C00",
		warn: "#8A5A00", err: "#B0281A"},
	{name: "ocean", label: "Ocean",
		brandFG: "#F4F8FC", brandBG: "#1F5F99", section: "#7FB8F0", muted: "#8C9BAD", label_: "#9FB0C4", selected: "#F4F8FC",
		public: "#F0C674", address: "#7FDBEB", port: "#8FE3B8", protocol: "#C9A7F5", enabled: "#6FD0A0", disabled: "#E8A06A",
		keyFG: "#0B1B2B", keyBG: "#7FB8F0", message: "#F0D28A", messageBorder: "#7FB8F0",
		accent: "#2A5D8F", quiet: "#2C3E50", selectedBorder: "#7FB8F0", value: "#DCE6F0", focused: "#F0C674",
		warn: "#F0D28A", err: "#F07A6A"},
	{name: "plain", label: "Plain (no colors)", plain: true},
}

func findTheme(name string) tuiTheme {
	for _, t := range tuiThemes {
		if t.name == name {
			return t
		}
	}
	return tuiThemes[0]
}

func nextTheme(name string) tuiTheme {
	for i, t := range tuiThemes {
		if t.name == name {
			return tuiThemes[(i+1)%len(tuiThemes)]
		}
	}
	return tuiThemes[0]
}

func applyTheme(t tuiTheme) {
	color := func(v string) lipgloss.TerminalColor {
		if t.plain || v == "" {
			return lipgloss.NoColor{}
		}
		return lipgloss.Color(v)
	}
	text := func(v string, bold bool) lipgloss.Style { return lipgloss.NewStyle().Bold(bold).Foreground(color(v)) }
	brandStyle = lipgloss.NewStyle().Bold(true).Foreground(color(t.brandFG)).Background(color(t.brandBG)).Padding(0, 1)
	keyStyle = lipgloss.NewStyle().Bold(true).Foreground(color(t.keyFG)).Background(color(t.keyBG))
	if t.plain {
		brandStyle, keyStyle = brandStyle.Reverse(true), keyStyle.Reverse(true)
	}
	sectionStyle = text(t.section, true)
	mutedStyle = text(t.muted, false)
	labelStyle = text(t.label_, false)
	selectedStyle = text(t.selected, true)
	publicStyle = text(t.public, true)
	addressStyle = text(t.address, true)
	portStyle = text(t.port, true)
	protocolStyle = text(t.protocol, true)
	enabledStyle = text(t.enabled, true)
	disabledStyle = text(t.disabled, true)
	warnStyle = text(t.warn, false)
	errStyle = text(t.err, true)
	if t.plain {
		disabledStyle = disabledStyle.Underline(true)
	}
	messageStyle = lipgloss.NewStyle().Foreground(color(t.message)).BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).BorderForeground(color(t.messageBorder)).PaddingLeft(1)
	valueStyle = text(t.value, false)
	focusedStyle = text(t.focused, true)
	if t.plain {
		focusedStyle = focusedStyle.Underline(true)
	}
	accentBorder, quietBorder, selectedBorder = color(t.accent), color(t.quiet), color(t.selectedBorder)
}

// The chosen theme is remembered per user.
func themeFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "meshgate", "tui-theme")
}

func loadTheme() tuiTheme {
	if f := themeFile(); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return findTheme(strings.TrimSpace(string(b)))
		}
	}
	return tuiThemes[0]
}

func saveTheme(name string) {
	if f := themeFile(); f != "" {
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, []byte(name+"\n"), 0o644)
	}
}

func init() { applyTheme(tuiThemes[0]) }
