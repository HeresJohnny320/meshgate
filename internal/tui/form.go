package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type fieldKind int

const (
	fText fieldKind = iota
	fBool
	fChoice
)

type option struct{ label, value string }

type field struct {
	key     string
	label   string
	kind    fieldKind
	input   textinput.Model
	on      bool
	options []option
	idx     int
}

func (f *field) value() string {
	switch f.kind {
	case fBool:
		if f.on {
			return "true"
		}
		return "false"
	case fChoice:
		if len(f.options) == 0 {
			return ""
		}
		return f.options[f.idx].value
	}
	return strings.TrimSpace(f.input.Value())
}

// form is a small vertical form: tab/shift-tab or ↑/↓ move, space toggles,
// ←/→ change choices, enter on the last field (or ctrl+s) submits.
type form struct {
	title  string
	fields []*field
	focus  int
	err    string
	submit func(map[string]string) error
	done   bool
}

func newForm(title string, submit func(map[string]string) error) *form {
	return &form{title: title, submit: submit}
}

func (f *form) text(key, label, val, placeholder string) *form {
	ti := textinput.New()
	ti.Prompt = ""
	ti.SetValue(val)
	ti.Placeholder = placeholder
	ti.CharLimit = 512
	ti.Width = 44
	f.fields = append(f.fields, &field{key: key, label: label, kind: fText, input: ti})
	return f
}

func (f *form) toggle(key, label string, on bool) *form {
	f.fields = append(f.fields, &field{key: key, label: label, kind: fBool, on: on})
	return f
}

func (f *form) choice(key, label string, opts []option, current string) *form {
	fl := &field{key: key, label: label, kind: fChoice, options: opts}
	for i, o := range opts {
		if o.value == current {
			fl.idx = i
		}
	}
	f.fields = append(f.fields, fl)
	return f
}

func (f *form) init() *form {
	f.setFocus(0)
	return f
}

func (f *form) setFocus(i int) {
	if i < 0 {
		i = len(f.fields) - 1
	}
	if i >= len(f.fields) {
		i = 0
	}
	for j, fl := range f.fields {
		if fl.kind == fText {
			if j == i {
				fl.input.Focus()
			} else {
				fl.input.Blur()
			}
		}
	}
	f.focus = i
}

func (f *form) values() map[string]string {
	out := map[string]string{}
	for _, fl := range f.fields {
		out[fl.key] = fl.value()
	}
	return out
}

// update returns true when the form should close.
func (f *form) update(msg tea.Msg) (bool, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return false, nil
	}
	cur := f.fields[f.focus]
	switch km.String() {
	case "esc":
		return true, nil
	case "tab", "down":
		f.setFocus(f.focus + 1)
		return false, nil
	case "shift+tab", "up":
		f.setFocus(f.focus - 1)
		return false, nil
	case "ctrl+s":
		return f.trySubmit(), nil
	case "enter":
		if f.focus == len(f.fields)-1 {
			return f.trySubmit(), nil
		}
		f.setFocus(f.focus + 1)
		return false, nil
	}
	switch cur.kind {
	case fBool:
		if km.String() == " " || km.String() == "left" || km.String() == "right" {
			cur.on = !cur.on
		}
	case fChoice:
		switch km.String() {
		case "left", "h":
			cur.idx = (cur.idx - 1 + len(cur.options)) % len(cur.options)
		case "right", "l", " ":
			cur.idx = (cur.idx + 1) % len(cur.options)
		}
	case fText:
		var cmd tea.Cmd
		cur.input, cmd = cur.input.Update(msg)
		return false, cmd
	}
	return false, nil
}

func (f *form) trySubmit() bool {
	if err := f.submit(f.values()); err != nil {
		f.err = err.Error()
		return false
	}
	return true
}

func (f *form) view(width int) string {
	inner := innerWidth(width)
	body := []string{line(inner, brandStyle.Render(strings.ToUpper(f.title))), ""}
	for i, fl := range f.fields {
		marker, style := "  ", valueStyle
		if i == f.focus {
			marker, style = selectedStyle.Render("> "), focusedStyle
		}
		var val string
		switch fl.kind {
		case fText:
			fl.input.Width = max(10, inner-32)
			if i == f.focus {
				val = fl.input.View()
			} else {
				val = style.Render(dash(fl.input.Value()))
			}
		case fBool:
			val = style.Render("[ ] no")
			if fl.on {
				val = style.Render("[x] yes")
			}
		case fChoice:
			if len(fl.options) > 0 {
				val = style.Render("< " + fl.options[fl.idx].label + " >")
			}
		}
		body = append(body, line(inner, marker+labelStyle.Render(fmt.Sprintf("%-28s", fl.label+":"))+" "+val))
	}
	out := []string{panel(width, accentBorder, body...),
		flow(width, helpKey("TAB/UP/DOWN", "move"), helpKey("SPACE/LEFT/RIGHT", "change"), helpKey("ENTER", "next / save on last"), helpKey("CTRL+S", "save"), helpKey("ESC", "cancel"))}
	if f.err != "" {
		out = append(out, messageStyle.Width(max(1, width-2)).Render(errStyle.Render(f.err)))
	}
	return lipgloss.JoinVertical(lipgloss.Left, out...)
}
