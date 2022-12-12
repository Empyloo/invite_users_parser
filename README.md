# invite_users
This Cloud Function is used to invite multiple users to join a company or organization. The function accepts a request with a list of email addresses, either directly in the request body or in a CSV file, and sends an invitation email to each of the specified email addresses. The invitation email contains a link that the user can use to create an account and join the company.

## Requirements
- Python 3.10
- Functions Framework 1.4.0
- Supabase 0.9.1
- Pandas 1.2.0

## Usage
To use this Cloud Function, you need to deploy it to a cloud provider that supports the Functions Framework. For example, you can deploy it to Google Cloud Functions using the cloudbuild.yaml file provided in this repository.

Once the function is deployed, you can send an HTTP POST request to the function's URL with the following parameters in the request body:

- `csv_file` (optional): The path to a CSV file containing the email addresses of the users to be invited. The CSV file must have a single column named emails that contains the email addresses.
- `emails` (optional): A list of the email addresses of the users to be invited. This parameter is required if the csv_file parameter is not provided.
- `role` (optional): The role to be assigned to the invited users. If not provided, the default role is user.
The request must also include an Authorization header with a valid JWT token that authenticates the request. The JWT token must be verified by the Supabase auth service before the function can send the invitation emails.

## Development
To develop this Cloud Function, you need to install the required packages using the requirements.txt file provided in this repository. You can install the packages using the following command:

```
pip install -r requirements.txt
```
Once the required packages are installed, you can run the invite_users function locally using the Functions Framework command:

```
functions-framework --target invite_users
```
This will start the Functions Framework development
