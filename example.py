import json
import fortiedr

def main():

   organization = "ORGANIZATION_NAME"

   authentication = fortiedr.auth(
      user="USER",
      passw="PASSWORD",
      host="FORTIEDR_HOST.COM", # use only the hostname, without 'https://' and '/'.
      org=organization          # Add organization IF needed. Case sensitive
   )

   if not authentication:

      print(authentication)

   else:

      # A example for getting Tenant administration data.
      #
      admin = fortiedr.Administrator()

      status, data = admin.list_system_summary(organization)
      if status:
         print("Management Hostname: ",     str(data['managementHostname']))
         print("Management Version: ",      str(data['managementVersion']))
         print("License Expiration Date: ", str(data['licenseExpirationDate']))
         print("External IP Address: ",     str(data['managementExternalIP']))
         print("Internal IP Address: ",     str(data['managementInternalIP']))
      else:
         print("Error in fetching data.")
      
      # 
      # An example of cloning the 'Execution Prevention' policy to another one called 'Cloned_Execution_Prevention'
      # 

      policies = fortiedr.Policies()
      status = policies.clone("Execution Prevention", "Cloned_Execution_Prevention", organization)
      if status:
         print("OK - Policy cloned")
      else:
         print("Error while cloning policy")

      # 
      # Listing all users in a organization
      # 

      u = fortiedr.Users()
      status, data = u.list_users(organization)
      if status:
         print(json.dumps(data, indent=4))

      # 
      # An example of creating a user
      #

      status = u.create_user(
         organization=organization,
         firstName="Username",
         lastName="Test API",
         password="TestUser123",
         confirmPassword="TestUser123",
         email="test-user@test.com",
         username="testapiuser",
         title="Test API",
         role="Admin",
         restApi=False,
         customScript=False,
         remoteShell=False
      )

      if status:
         print("User created!")
      else:
         print("Error while creating user...")
   
if __name__ == "__main__":
    main()
