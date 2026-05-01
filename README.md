# tripper

Brute-force tripcode finder for 2channel-style imageboards. Supports three tripcode algorithms used by different board software.

## Build

```
make
```

Produces three binaries, one per algorithm.

## Usage

Append the found password to your name as `#password` when posting to get the matching tripcode.

### tripper2ch — DES (2channel, Futaba, Futallaby, Electron, …)

```
./tripper2ch <search>
```

### trippershii — SHA1 (Shiichan, 4chan)

Requires a 448-byte salt file read from the board's source.

```
./trippershii <search> <salt-file>
```

### tripperc4 — RC4 (Wakaba, Wakaba-ZERO, Kareha)

```
./tripperc4 <search> <salt>
```

## Output

```
#password !tripcode
```

Search is case-insensitive by default. Build with `-DCASE_SENSITIVE` to change that. Build with `-DMAX_TRIPCODE_LEN=N` to search passwords up to length N (default 8).
