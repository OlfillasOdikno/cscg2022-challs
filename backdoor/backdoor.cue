package challenges

challenges: "backdoor": {
	enabled:     true
	displayName: "Backdoor"
	category:    "Reverse Engineering"
	difficulty:  "Hard"
	author:      "localo"
	broker:      "backdoor"
	brokerProtocol: "ssh"

	description: """
		Someone backdoored my PC and I lost access to the root account, I already figured out using my backups that ping has increased in size before I got owned, but I can't wrap my head around what it does, can you help me out? For convenience I provided both the original ping binary `ping-backup` as well as the backdoored one `ping`.
		"""

	deployment: {
		containers: [{
			image:     "backdoor"
			buildRoot: "deploy/setup"
		}]
	}

	points: 100
	flag:   "CSCG{i_like_chains_rop_go_brrr}"

	files: [{
		name:      "backdoor.zip"
		sha256sum: "cc034c54ecb5d80a9ccc9b00eaac6b761bffd3a0d26ce60d1bac18918e6e0c61"
	}]
}
