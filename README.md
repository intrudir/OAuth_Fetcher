# OAuth-Fetcher
Burp extension that allows you to fetch/renew oauth creds &amp; access tokens for your requests automagically!


## Based on the old ext by @bb_hacks
https://github.com/t3hbb/OAuthRenew
<br>

This tool will allow you to generate a signed JWT using OAuth client ID and credentials.

It will get the client assertion and then request a Bearer token.

If it recognizes that your token has expired, it will get a new one and replace it for subsequent requests :)
<br>

---
## Set up
Modify the extension as necessary:  

Enter your client credentials & extra params  
![image](https://user-images.githubusercontent.com/24526564/186030136-069d55a9-8384-47b2-92da-e3d40e2f797d.png)

Make adjustments to the POST parameters if needed.  
If you have any extra params, make sure you include them here.
![image](https://user-images.githubusercontent.com/24526564/186029622-e57032b8-4ef5-4a5a-94d9-5971b7552aed.png)

At the moment, the tool only works in Repeater. You can modify this here:
![image](https://user-images.githubusercontent.com/24526564/186030417-de765e7a-7fe9-4892-83c3-3e235f2e4fd7.png)

The extension checks for your specified token expired/error text.
![image](https://user-images.githubusercontent.com/24526564/186029237-d4c6dfb4-1aaa-4a45-89f2-e07a166f6a36.png)

Install the extension. Enjoy!
![image](https://user-images.githubusercontent.com/24526564/186040666-533a199f-cc3d-49e9-9113-efdfc08396ef.png)


<br>

---
## Usage
### Example in Repeater
It will detect that the token has expired or is invalidated.
![image](https://user-images.githubusercontent.com/24526564/186031190-48d5811a-e4de-4eaf-93de-0bfe787471f1.png)
<br>

### Simply check the output in the Extender tab.   
NOTE: Sometimes you need to issue the request twice.
![image](https://user-images.githubusercontent.com/24526564/186032197-b185527e-d13c-49cd-a4d0-c35e482af191.png)

Observe that your subsequent requests should be properly authenticated.  
NOTE: The token in your request might still look like the old one. The extension is handling it with the new token. (Trying to figure this out :) )
![image](https://user-images.githubusercontent.com/24526564/186032447-4284ec03-319a-4555-9ab0-0f7744ad096a.png)
<br>

---
## Troubleshooting
If something doesn't work, check the output console in Extender tab. It will retry at least 3 times to refresh the token before giving up.

