# The README's demo: lsnet browsing the made-up network (`--demo`), so it
# shows no one's real devices. To record it again, from the repo's root:
#
#   cargo build --release && vhs docs/demo.tape
#
# Needs vhs (https://github.com/charmbracelet/vhs). Nothing is scanned,
# copied or opened, and with HOME set aside the theme picked isn't saved.

Output docs/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1180
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set Framerate 15
Set TypingSpeed 60ms

Hide
Type 'export PATH="$PWD/target/release:$PATH" HOME="$(mktemp -d)" && clear'
Enter
Show

Type "lsnet --demo"
Sleep 600ms
Enter
Sleep 2.5s

# Down the list, the details following: the printer, the NAS, the Apple TV.
Down 3
Sleep 2s
Down
Sleep 1.5s
Down 2
Sleep 2s

# Filter.
Type "/"
Sleep 400ms
Type "speaker"
Sleep 1.8s
Escape
Sleep 800ms

# Every service on the network.
Type "2"
Sleep 1.5s
Down@180ms 8
Sleep 2s

# Themes, previewed as you move.
Type "t"
Sleep 1s
Down@350ms 8
Sleep 800ms
Enter
Sleep 2s

# Back to devices, in the theme just picked.
Type "1"
Sleep 3s
