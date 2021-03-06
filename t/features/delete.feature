Feature: Deleting entries from the directory
 As a directory consumer
 I want to ensure that I can delete entries from the directory
 In order to remove information

 Background:
   Given a usable Net::LDAPapi class

 Scenario: Can remove an entry from the directory
   Given a Net::LDAPapi object that has been connected to the LDAP server
   When I've bound with default authentication to the directory
   And a test container has been created
   And I've added a new entry to the directory
   And I've deleted the new entry from the directory
   Then the new entry result is LDAP_SUCCESS
   And the delete entry result is LDAP_SUCCESS
   And the test container has been deleted

 Scenario: Can asynchronously remove an entry from the directory
   Given a Net::LDAPapi object that has been connected to the LDAP server
   When I've asynchronously bound with default authentication to the directory
   And a test container has been created
   And I've asynchronously added a new entry to the directory
   And I've asynchronously deleted the new entry from the directory
   Then after waiting for all results, the new entry result message type is LDAP_RES_ADD
   And the new entry result is LDAP_SUCCESS
   And after waiting for all results, the delete entry result message type is LDAP_RES_DELETE
   And the delete entry result is LDAP_SUCCESS
   And the test container has been deleted
