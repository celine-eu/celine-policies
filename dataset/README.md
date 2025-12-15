# Dataset Access Policies

OPA policies governing access to datasets in the CELINE platform.

## Disclosure levels

| Level       | Description                                 |
|------------|---------------------------------------------|
| open       | Anonymous access (OPA not involved)          |
| green      | Auth required, no policy check               |
| internal   | Auth + DATA_USER role                        |
| restricted | Auth + dataset owner only                   |

## Input contract

OPA receives:

```json
{
  "dataset": {
    "id": "dataset_id",
    "disclosure_level": "internal | restricted",
    "governance": {
      "owner": "user-id"
    }
  },
  "user": {
    "sub": "user-id",
    "roles": ["DATA_USER"]
  }
}
