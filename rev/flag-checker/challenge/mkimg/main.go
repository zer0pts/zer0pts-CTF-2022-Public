package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"os"
	"strconv"
	"strings"

	"github.com/fogleman/gg"
	"golang.org/x/image/bmp"
)

func mkcolor(ch byte, bits uint) string {
	path := "GR"
	m := map[string]string{
		"G0": "GR",
		"G1": "RG",
		"R0": "RG",
		"R1": "GR",
	}
	var ans string = "GR"
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
	ans = strings.ReplaceAll(ans, "G", "0")
	return strings.ReplaceAll(ans, "R", "1")
}

func check_resolution(width, height int, flag string) bool {
	np := 0
	for i := 0; i < width*height; i++ {
		if is_prime(i) {
			np++
		}
	}
	color_len := 0
	for _, r := range flag {
		color_len += len(mkcolor(byte(r), 8))
	}
	return np >= color_len
}

func is_prime(param int) bool {
	// var isp bool = true
	if param < 2 {
		return false
	}
	for j := 2; j*j <= param; j++ {
		if param%j == 0 {
			return false
		}
	}
	return true
}

func mkflag() string {
	var flag_str string = "me$s4g3_p4$$1ng_thru|p1pez_4r3_gr347!"
	h := sha256.New()
	h.Write([]byte(flag_str))
	h32 := h.Sum(nil)
	suffix := hex.EncodeToString(h32)
	flag_str = "zer0pts{" + flag_str + suffix + "}"
	return flag_str
}

func genimg() {
	msg := "No flag for you!"
	ctx := gg.NewContext(1920, 1080)
	ctx.LoadFontFace("Source_Code_Pro/static/SourceCodePro-Regular.ttf", 120)

	ctx.SetRGB(10/255.0, 10/255.0, 10/255.0)
	ctx.DrawRectangle(10, 10, float64(ctx.Width())-10, float64(ctx.Height())-10)
	ctx.FillPreserve()

	ctx.SetRGB(240/255.0, 63/255.0, 43/255.0)
	text_w, text_h := ctx.MeasureMultilineString(msg, 1.5)
	ctx.DrawString(msg, float64(ctx.Width())/2-text_w/2,
		float64(ctx.Height())/2-text_h/2,
	)

	f, _ := os.Create("gen.bmp")
	defer f.Close()
	bmp.Encode(f, ctx.Image())
	ctx.SavePNG("gen.png")
}

func main() {
	flag_str := mkflag()
	fmt.Println(flag_str)
	fmt.Println("Generating image...")
	genimg()
	f, _ := os.Open("IMG_4155.jpg")
	defer f.Close()
	im, _ := jpeg.Decode(f)
	size := im.Bounds()
	width := size.Dx()
	height := size.Dy()
	if !check_resolution(width, height, flag_str) {
		fmt.Println("Sorry. Need a bigger resolution")
		return
	}
	env_v := os.Getenv("BIT_SIZE")
	if env_v == "" {
		env_v = "8"
	}
	n_bits, _ := strconv.Atoi(env_v)
	fmt.Printf("Bit Size: %d\n", n_bits)
	var flag_bits string
	for _, r := range flag_str {
		flag_bits += mkcolor(byte(r), uint(n_bits))
	}

	var col, row, pos int
	temp_img := image.NewRGBA(im.Bounds())
	draw.Draw(temp_img, temp_img.Bounds(), im, im.Bounds().Min, draw.Src)

	fimg := image.NewRGBA(im.Bounds())
	flag_pos := 0
	for col = 0; col < (height); col++ {
		for row = 0; row < (width); row++ {
			// pos = col*width + row
			pos = temp_img.PixOffset(row, col) >> 2
			old_color := temp_img.At(row, col)
			// old_color = color.RGBAModel.Convert(old_color)
			clr := old_color.(color.RGBA)
			if (flag_pos < len(flag_bits)) && is_prime(pos) {
				clr.R &= 0xfe
				clr.R |= flag_bits[flag_pos] - 0x30
				flag_pos += 1
			}
			fimg.Set(row, col, clr)
		}
	}
	fmt.Println(fimg.Pix[0:3])
	fx, _ := os.Create("image.png")
	png.Encode(fx, fimg)
}
