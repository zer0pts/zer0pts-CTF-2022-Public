package main

import (
	"bytes"
	"fmt"
	"image/png"
	"log"
	"os"

	"golang.org/x/sys/windows"
)

func mkcolor(ch byte, bits uint) string {
	path := "01"
	m := map[string]string{
		"00": "01",
		"01": "10",
		"10": "10",
		"11": "01",
	}
	var ans string = "01"
	for i := uint(0); i < bits; i++ {
		bit := (ch >> i) % 2
		t := ""
		for _, cc := range path {
			xp := string(cc) + string(rune(0x30+bit))
			k := m[xp]
			l := k[0]
			r := k[1]
			p := string(rune(l))
			p += string(rune(r))
			ans += p
			t += p
		}
		path = t
	}
	return ans
}

func isPrime(n int) bool {
	if n == 2 {
		return true
	}
	if n < 2 || n > 2 && n%2 == 0 {
		return false
	}
	for i := 3; i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}

func main() {
	image, err := windows.LoadLibraryEx("../task.exe", 0, windows.LOAD_LIBRARY_AS_IMAGE_RESOURCE)
	check_err(err)
	res, err := windows.FindResource(image, windows.ResourceID(12), windows.RT_ICON)
	check_err(err)
	img, err := windows.LoadResourceData(image, res)
	check_err(err)

	im, err := png.Decode(bytes.NewReader(img))
	check_err(err)
	// f, _ := os.Create("temp.png")
	// png.Encode(f, im)
	bnd := im.Bounds()
	width, height := bnd.Dx(), bnd.Dy()

	cache := make(map[string]byte)
	var chunk_size = -1
	for ch := 0; ch < 256; ch++ {
		cc := mkcolor(byte(ch), 8)
		cache[cc] = byte(ch)
		if chunk_size == -1 {
			chunk_size = len(cc)
		}
	}

	var flag []byte
	var col, row, pos int
	var temp_str []byte
outer:
	for col = 0; col < height; col++ {
		for row = 0; row < width; row++ {
			pos = col*width + row
			if isPrime(pos) {
				r, _, _, _ := im.At(row, col).RGBA()
				if len(temp_str) == chunk_size {
					if val, ok := cache[string(temp_str)]; ok {
						flag = append(flag, val)
					} else {
						break outer
					}
					temp_str = []byte{}
				}
				temp_str = append(temp_str, byte((r>>8)%2+0x30))
			}
		}
	}
	fmt.Println(string(flag))
}

func check_err(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
