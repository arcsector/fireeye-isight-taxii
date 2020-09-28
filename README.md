# FireEye iSight TAXII Connector

This is an implementation of the FireEye iSight API connector with added TAXII connectors for facilitaion with TAXII v1.

## Installation

Install requirements with:

```bash
python3 -m pip install cabby

### OR ###

python3 -m pip install -r requirements.txt
```

## How to Use

Simply import the file, create a class instance, initialize it, and then you're good to go:

```python
from datetime import datetime, timedelta, timezone
from endpoint_query import APIRequestHandler

if __name__ == '__main__':
    public_key = 'PUBLIC'
    private_key = 'PRIVATE'
    format_ = "application/stix"
    content_binding = "urn:stix.mitre.org:xml:1.1.1"

    # create class instance
    api = APIRequestHandler()

    # initialize class instance
    api.init(public_key=public_key, private_key=private_key)

    # Get IoCs for default time range
    j = api.getIocs()

    for report in j['message']:
        timestamp = datetime.fromtimestamp(report['publishDate'], tz=timezone.utc)

        # Get detailed IoC reports in STIX format
        r = api.getReport(reportId=report['reportId'], accept_header=format_)

        # Send to TAXII server
        stix = api.taxiiPush(
            username="user",
            password="pass",
            content=r,
            content_binding=content_binding,
            collection_names=["mycollection"],
            timestamp=timestamp,
            uri="http://taxiistand.com/services/inbox"
        )
        file_name = stix.id_

        print(file_name + " uploaded to TAXII server")
```
