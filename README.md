Go to appstore on macos and install xcode developer utils

Then run to fix xcode crap
1. xcode-select --switch /Applications/Xcode.app/Contents/Developer 

To compile run
1. xcrun -sdk macosx metal -c HashAndMatch.metal -o HashAndMatch.air && xcrun -sdk macosx metallib HashAndMatch.air -o libHashAndMatch.metallib

Then its just `cargo run --release -- 00000000` where `00000000` is the prefix it'll look for. change it to your need.