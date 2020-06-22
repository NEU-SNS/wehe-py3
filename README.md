# Wehe

This software is covered by the CRAPL licence (see CRAPL-LICENSE.txt)

##How to run a replay step by step:

On the server:

* Change the content in folders.txt to where the replay pickle is (in this example, it can be ../replayTraces/Youtube and ../replayTraces/YoutubeRandom)
* You can now run the replay_server and replay analyzer with
```bash
./restartServers.sh
```

On the client:

* Assume the server used is wehe3.meddle.mobi (can use your own server as well, just edit ```class Instance``` in python_lib.py). You can then run a replay of the recorded traffic

```bash
python3 replay_client.py --pcap_folder={the/dir/to/replayFiles} --serverInstance=wehe
```

## Containerization

This tool has been containerized. To run it within a container first go to the cloned directory and build with
```bash
docker build . -t wehe
```

Then run with 
```bash
docker run -v /data:/data --net=host --env SUDO_UID=$UID -itd wehe {the public IP address/ hostname}
```

/data is where the results are saved
Remove d from `-itd` to run outside of detached mode and see the output in STDOUT


##For SSL encryption:

run certGenerator.py to generate your own certificate that can be used to encrypt sidechannel communications.

## Creat your own test
Prepare the replay traffic, the replay is recorded in a pcap file, and we will use the parser script to process the pcap and create the pickle file that can be used by the client and server.

Assume the pcap is stored in the/dir/to/pcap. Copy the same pcap to the/dir/to/pcapRandom.

Create a file named client_ip.txt in both directories, with the only content in it be the client's ip in the pcap file.

On the client:

* Create the replay file with original payload

```bash
sudo python3 replay_parser.py --pcap_folder={the/dir/to/pcap}
```

* Creat the replay file with bit-inverted payload

```bash
sudo python3 replay_parser.py --pcap_folder={the/dir/to/pcapRandom} --randomPayload=True --invertBit=True
```

* Copy the pickle directory (the/dir/to/pcap, and the/dir/to/pcapRandom) to the server via scp

