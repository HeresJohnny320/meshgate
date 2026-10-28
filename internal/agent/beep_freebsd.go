package agent

import (
	"os"
	"os/exec"
	"strconv"
)

// beep plays a short tune on the PC speaker: falling when a link went down,
// rising when it is back. pfSense ships /usr/local/bin/beep (the one its
// startup sound uses); otherwise speaker(4) plays the same notes.
func beep(down bool) {
	tones, notes := [][2]int{{880, 150}, {660, 150}, {440, 350}}, "T200 O5 L8 A E O4 L4 A"
	if !down {
		tones, notes = [][2]int{{660, 120}, {990, 250}}, "T200 O5 L8 E L4 B"
	}
	if _, err := os.Stat("/usr/local/bin/beep"); err == nil {
		for _, t := range tones {
			exec.Command("/usr/local/bin/beep", "-p", strconv.Itoa(t[0]), strconv.Itoa(t[1])).Run()
		}
		return
	}
	exec.Command("kldload", "-n", "speaker").Run()
	if f, err := os.OpenFile("/dev/speaker", os.O_WRONLY, 0); err == nil {
		f.WriteString(notes)
		f.Close()
	}
}
