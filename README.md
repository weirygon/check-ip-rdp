# Description 📜
This script utilizes the [AbuseIPDB API](https://docs.abuseipdb.com/#check-endpoint). When a connection is **established** on port 3389, the trigger is activated, which executes the script. Based on the API response, the IP is blocked in the firewall.

# Configuration ⚙️
There are some configurations to be made before running the script:
[Const to configure](https://github.com/weirygon/check-ip-rdp/blob/18d941a37c83bc60d953b96c24856de4117341ee/checkMaliciousIP.py#L6-L8)

```python
6 | filter_Score = 65
7 | api_key = 'YOUR_OWN_API_KEY'
8 | locate_dir = ((os.environ.get('SystemRoot')) + '\\System32\\LogFiles\\checkMaliciousIP')
```
- **filter_Score**: This constant determines the score threshold that will serve as the cutoff point, default `>=65`.
- **api_key**: This variable should contain your API token, which you can find in the [API](https://www.abuseipdb.com/account/api) tab of your AbuseIPDB account.
- **locate_dir**: This constant is responsible for the path where logs will be saved, default `%SystemRoot%\System32\LogFiles\checkMaliciousIP`.
> [!CAUTION]
> Depending on your application's usage, it may exceed the daily request limit, and the script will no longer block IPs even if they are malicious. See [Rate Limit](https://docs.abuseipdb.com/#api-daily-rate-limits)

# Bundle 📦
> [!NOTE]
> This step is **OPTIONAL**, but I recommend it.

After configuring the constants, let's bundle the .py file into a .exe. For this, it's important to install *pyinstaller*.

```
pip install pyinstaller
```

Once installed, use the following command:

```
pyinstaller --onefile checkMaliciousIP.py
```

This command will create a `.exe` file in the `./dist` folder.

# Installation 🔌
