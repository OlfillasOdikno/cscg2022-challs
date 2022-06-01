package challenges

shared_description: """
		There are two versions of the bootloader, one with a test key and one with a production key.
		This challenge has three stages, 
		- first you need to obtain the test bootloader image
		- then you have to reverse engineer it and sign your own image with the test key
		- at the end you have to sign the image with the production key to prove that you are l33t

		The flag for each stage in on an attached drive. Details on the deployment can be found in the Dockerfile.
		
		Example input:

		    31c08ed831c0cd10b401b90726cd10b603b9120051fec6b20db90e00bb78
		    00e8b60080fe15740942b90c0031dbe8a80059e2e1c606007f64b402cd1a
		    a0027f31d0b31ff7e340a2027f31d2bb0700f7f3c0e20392ba1204e8e500
		    75fee8d20031c98a0e007f516031c9bab80bb486cd156150b401cd1689c1
		    587445e8af0080fd4b741180fd48741e80fd4d7410c606007f0aeb234ae8
		    a700741d42eb1a42e89e0074144aeb1188c34040a80775022c08e88c0074
		    0288d8e877005030e4cd165859e2a2e86700fec6e87400748afecee85f00
		    e81600e95bffb402cd10b82009cd10c3b402cd10b408cd10c360b615fece
		    743931dbb90c00b20ee8e6ffc0ec0474024342e2f480fb0c75e460b20eb9
		    0c0051fecee8ccfffec688e3b101e8b9ff4259e2ed61fece75e2e8c0ff61
		    c331dbeb0988c3c0eb0343c0e3044389dfeb03bf00006031db88c38b8786
		    7d31dbb9040051b104f6c480741d5009ff740e6089fb30c0b90100e870ff
		    61eb09e874ffc0ec0474014358d1e042e2d980ea04fec659e2ce08db61c3
		    444400f0444400f0602200e24064008e6044002e206200e8006600660066
		    006600c6402600c64026004e404c00e4808c006c408c006c408c80000100
		    170002000000000002000000000000000000000000000000000000000000
		    000000000000000000000000000000000000000000000000000000000000
		    55aa48f9b919b57d19d4EOF

		I have also test-signed 4 programs.
		Tetros is from <https://github.com/daniel-e/tetros> and the other three are from <https://github.com/nanochess>.

		Btw. the sha256sum of the test bootloader image is: `9daffe370e2270e316cfdb4787e2a84cb7e8781e875a02f3cb8973f4e22a3f76`
		"""

challenges: "secureboot": {
	enabled:     true
	displayName: "Secureboot"
	category:    "Pwn"
	difficulty:  "Hard"
	author:      "localo"
	broker:      "secureboot"

	description: shared_description

	deployment: {
		containers: [{
			image:     "secureboot"
			buildRoot: "deploy/setup"
			build:     true
		}]
	}

	points: 100
	flag:   "CSCG{cyber_cyber_hax_hax!11!!1}"

	files: [{
		name:      "secureboot.zip"
		sha256sum: "6560f2039c0fe3511c6de9cd7675b20d580e2ea70f760bbd4794a56c67f738d9"
	}]
}

challenges: "secureb00t": {
	enabled:     true
	displayName: "Secureb00t"
	category:    "Reverse Engineering"
	difficulty:  "Medium"
	author:      "localo"
	broker:      "secureboot"

	description: shared_description

	deployment: {
		containers: [{
			image:     "secureboot"
			buildRoot: "deploy/setup"
			build:     false
		}]
	}

	points: 100
	flag:   "CSCG{can_this_even_run_on_real_hardware?!}"

	files: [{
		name:      "secureboot.zip"
		sha256sum: "6560f2039c0fe3511c6de9cd7675b20d580e2ea70f760bbd4794a56c67f738d9"
	}]
}


challenges: "53cur3b00t": {
	enabled:     true
	displayName: "53cur3b00t"
	category:    "Crypto"
	difficulty:  "Medium"
	author:      "localo"
	broker:      "secureboot"

	description: shared_description

	deployment: {
		containers: [{
			image:     "secureboot"
			buildRoot: "deploy/setup"
			build:     false
		}]
	}

	points: 100
	flag:   "CSCG{The S-box is left undefined; the implementation can simply use whatever data is available in memory. - https://en.wikipedia.org/wiki/Treyfer}"

	files: [{
		name:      "secureboot.zip"
		sha256sum: "6560f2039c0fe3511c6de9cd7675b20d580e2ea70f760bbd4794a56c67f738d9"
	}]
}
