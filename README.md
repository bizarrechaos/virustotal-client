# virustotal-client
### unofficial virustotal python client

---

# Install instructions
- Clone this repository
  ```
  git clone git@github.com:bizarrechaos/virustotal-client.git
  ```
- Install the requirements
  ```
  sudo pip install -r requirements.txt
  ```
- Initialize the config file
  ```
  ./vtc.py init --virustotal VIRUSTOTAL_APIKEY [--googl GOOGL_APIKEY]
  ```
  Login in or create a virustotal account [here](https://www.virustotal.com/).  
  Optionally if you would like to shorten urls with googl follow [this](https://developers.google.com/api-client-library/python/auth/api-keys) guide to obtain your apikey

# Usage
To view the help text use -h
```
./vtc.py -h
```
## init
This is the command we just used to create the config file.  
If you ever lose your config file or your apikeys change just rerun the command.
```
./vtc.py init --virustotal VIRUSTOTAL_APIKEY [--googl GOOGL_APIKEY]
```
## report
This is the command used to get reports from virsustotal.  

## scan
This is the command used to upload files to or request url scans from virustotal.  

## sha256
This command will return the sha256 hash of a file.  

## signature
This command will print the file signature (first 8 octets) from a files hex.  


# options

## apikey
You can bypass the virustotal apikey in the config file anytime by supplying one at runtime.  

## json
By default all output will be ascii tables or plain text.  
This option allows you to output in json.  

# Thanks
- @jwalker for the [virustotal module](https://github.com/jwalker/Virustotal-Module).
- @igrishaev for the [googl module](https://github.com/igrishaev/googl-python).
