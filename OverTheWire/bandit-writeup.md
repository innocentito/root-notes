# OverTheWire Bandit – Walkthrough (Levels 0–14)

**Game:** OverTheWire Bandit  
**Difficulty:** Absolute Beginner  
**What it teaches:** Linux basics, file handling, SSH, compression, encoding

So Bandit is basically the "hello world" of wargames. It teaches you how to move around a Linux system, read files, and deal with annoying filenames. Sounds easy but some of these levels have little gotchas that'll trip you up if you're not paying attention. Here's how I got through each one.

---

## Level 0

Just SSH into the server. Nothing fancy.

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

Password is `bandit0`. Once you're in there's a `readme` file sitting right there.

```bash
cat readme
```

Password: `ZjLjTmM6FvvyRnrb2rfNWOZOTa6i****`

---

## Level 1

The file is literally called `-`. The problem is that `cat -` tells cat to read from stdin instead of opening a file. So you gotta trick it by giving it a path:

```bash
cat ./-
```

There's other ways too like `cat < -` or `cat $(pwd)/-` but `cat ./-` is the shortest.

Password: `263JGJPfgU6LtdEvgfWU1XP5yac2****`

---

## Level 2

Filename has spaces in it: `--spaces in this filename--`. Spaces break commands because the shell thinks each word is a separate argument. Wrap it in quotes:

```bash
cat "./--spaces in this filename--"
```

Or use backslashes to escape each space. Or be lazy and use find:

```bash
find . -name "*spaces*" -exec cat {} \;
```

Password: `MNk8KNH3Usiio41PRUEoDFPqfxLP****`

---

## Level 3

File is hidden. Hidden files in Linux start with a dot and `ls` won't show them by default. Find it with:

```bash
find . -type f
```

Then cat whatever it finds.

Password: `2WmrDFRmJIq3IPxneAaMGhap0pFh****`

---

## Level 4

There's 10 files in a directory and only one has the password. All filenames start with `-` so you need the `./` prefix. Quickest way is to check which one is human readable:

```bash
file ./-*
```

Only one will say "ASCII text" – that's your target.

Password: `4oQYVPkxZOOEOO5pTW81FB8j8lxX****`

---

## Level 5

Tons of directories with tons of files. The description says the password file is human-readable, 1033 bytes, and not executable. So just let find do the filtering:

```bash
find ./ -type f -size 1033c ! -executable -exec cat {} \;
```

One file matches all three conditions.

Password: `HWasnPhtq9AVKe0dmk45nxy20cvU****`

---

## Level 6

Password is somewhere on the entire server, owned by user bandit7, group bandit6, 33 bytes. Search from root and suppress all the permission denied noise:

```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

Spits out one path, cat it, done.

Password: `morbNTDkSW6jIlUc0ymOdMaLnOlF****`

---

## Level 7

Password is in `data.txt` next to the word "millionth". File is huge so don't scroll through it manually:

```bash
grep "millionth" data.txt
```

Password: `dfwvzFQi4mU0wfNbFOe9RoWskMLg****`

---

## Level 8

Password is the only line that appears exactly once in `data.txt`. Sort first so duplicates are next to each other, then use uniq to find the unique one:

```bash
sort data.txt | uniq -u
```

Password: `4CKMh1JI91bUIZZPXDqGanal4xvA****`

---

## Level 9

Binary file with some readable strings in it. Password is next to a bunch of `=` characters. Pull out all human-readable strings and filter:

```bash
strings data.txt | grep "=="
```

Password: `FGUW5ilLVJrxX9kMYMmlN4MgbpfM****`

---

## Level 10

File is base64 encoded. Just decode it:

```bash
base64 -d data.txt
```

Password: `dtR173fZKb0RRsDFSGsg2RWnpNVj****`

---

## Level 11

ROT13 encoded text. Every letter is shifted by 13 positions. Use `tr` to shift it back:

```bash
tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt
```

Password: `7x16WNeHIi5YkIhWsfFIqoognUTy****`

---

## Level 12

This one is annoying. The file is a hexdump of something that's been compressed multiple times. First reverse the hexdump:

```bash
xxd -r data.txt > data
```

Then it's a loop: run `file data` to see what compression it is (gzip, bzip2, or tar), decompress with the right tool, run `file` again, decompress again. Repeat until you get ASCII text.

The tools you'll rotate through:

```bash
file data              # check what it is
mv data data.gz        # rename for gzip
gzip -d data.gz        # decompress gzip
bzip2 -d data          # decompress bzip2
tar -xf data           # extract tar
```

There's like 6 or 7 layers of compression. Just keep going until `file` says it's text.

Password: `FO5dwFsc0cbaIiH0h8J2eUks2vdT****`

---

## Level 13

No password this time. Instead you get an SSH private key to log into bandit14 directly:

```bash
ssh -i sshkey.private -p 2220 bandit14@localhost
```

Once you're in as bandit14, grab the password from the password file:

```bash
cat /etc/bandit_pass/bandit14
```

Password: `MU4VWeTyJk8ROof1qqmcBPaLh7lD****`

---

## What I Learned

The hexdump level (12) was the most interesting one technically. `xxd -r` to reverse a hexdump is something I hadn't used before, and chaining `file` checks between decompressions is a solid methodology for dealing with nested archives in the wild. Recognizing magic bytes like `1f 8b` (gzip) or `42 5a` (bzip2) from a hex dump before even running `file` is a useful skill.

The SSH key level (13) is a good reminder that `-i` for identity files and `chmod 600` on private keys are non-negotiable. SSH will straight up refuse a key with loose permissions, which makes sense but is easy to forget.

Level 9 with `strings | grep` is basically the go-to approach for extracting readable data from binary blobs. Same technique works for firmware analysis, memory dumps, or any situation where you're pulling cleartext out of binary noise.

The `-print0 | xargs -0` pattern from level 2 is worth internalizing. Filenames with spaces, dashes, or special characters break naive pipes constantly. `-exec` avoids the problem entirely but `xargs -0` is faster when dealing with large file sets since it batches arguments instead of spawning a process per file.

---

## TODO

Level 15 through 34 are still on the list. Will update as I go.

Level 14, Level 15, Level 16, Level 17, Level 18, Level 19, Level 20, Level 21, Level 22, Level 23, Level 24, Level 25, Level 26, Level 27, Level 28, Level 29, Level 30, Level 31, Level 32, Level 33, Level 34.

---

*Educational purposes only. OverTheWire Bandit is a free wargame for learning Linux and security basics.*
