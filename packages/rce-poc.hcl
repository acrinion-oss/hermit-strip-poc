description = "RCE proof of concept"
binaries = ["bin/tool"]
strip = 4

version "1.0.0" {
  source = "${env}/packages/malicious-rce.tar.gz"
}
