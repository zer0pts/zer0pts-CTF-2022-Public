package;

import sys.io.File;

class Xorshift {
  private var x: UInt;
  private var y: UInt;
  private var z: UInt;
  private var w: UInt;

  public function new(x:UInt=0xdeadbeef,
                      y:UInt=0xcafebabe,
                      z:UInt=0x00ca7ca7,
                      w:UInt=0xca7eca7e) {
    this.x = x;
    this.y = y;
    this.z = z;
    this.w = w;
  }

  public function next(): UInt {
    var t = x ^ (x << 11);
    x = y;
    y = z;
    z = w;
    return w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));
  }
}

class Main
{
	macro static function swap(a, b) {
		return macro { var v = $a; $a = $b; $b = v; };
	}

  public static function main()
  {
    if (Sys.args().length != 1) {
      Sys.println("Usage: notcat <text file>");
      Sys.exit(1);
    }

    var path = Sys.args()[0];
    if (!sys.FileSystem.exists(path)) {
      Sys.stderr().writeString("File not found\n");
      Sys.exit(1);
    }

    var flag = StringTools.rtrim(sys.io.File.getContent(path));
    if (flag.length < 8) {
      Sys.println(flag);
      return;
    }

    var prefix = flag.substr(0, 8);
    if (prefix != "zer0pts{") {
      Sys.println(flag);
      return;
    }

    var rng = new Xorshift(
      flag.charCodeAt(0) + flag.charCodeAt(1) << 8,
      flag.charCodeAt(2) + flag.charCodeAt(3) << 8,
      flag.charCodeAt(4) + flag.charCodeAt(5) << 8,
      flag.charCodeAt(6) + flag.charCodeAt(7) << 8
    );
    Sys.print("fak3pts{");

    for (_ in 0...64) {
      var i = rng.next() % flag.length;
      var j = rng.next() % flag.length;
      if (i == j) {
        continue;
      } else if (i > j) {
        swap(i, j);
      }

      var a = String.fromCharCode(flag.charCodeAt(i) + (rng.next() % 3) - 1);
      var b = String.fromCharCode(flag.charCodeAt(j) + (rng.next() % 3) - 1);
      flag = flag.substring(0, i) + b
        + flag.substring(i+1, j) + a
        + flag.substring(j+1, flag.length);
    }

    Sys.print(flag);
    Sys.println("}");
  }
}
