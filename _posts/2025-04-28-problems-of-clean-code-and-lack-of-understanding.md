---
title: "Parsing and Validation: You should always understand what you are parsing and not be hyperfocused on clean code"
categories: [security]
tags: [security,parsing,validation,RFC,XMPP,XML]
---

## Introduction
Everyone wants to write clean code, but often the cleanest solution is not the most secure one. I will be discussing a real world example of a company that we will refer to as example.com that had a problem with parsing XMPP tags. I think this is a good example of how focusing too much on clean code can lead to security vulnerabilities. I will also be discussing how the lack of perfect understanding of anything that you are parsing can lead to security vulnerabilities. I will be using the XMPP RFC as an example, but this applies to any protocol that you are parsing and it is more crucial the more complicated protocol you are parsing.

## Terms used in this post
- XMPP - Extensible Messaging and Presence Protocol. A protocol for streaming XML over the internet. It is used for instant messaging, presence information and contact list maintenance. 

 - XMPP tags - XML tags that are used in XMPP. They are used to define the structure of the XML document and to define the data that is being sent. 

 - XMPP JID - Jabber ID. A unique identifier for a user in XMPP. It's basically a username and is used to identify users within the network. It is usually in the form of username@domain/resource. The resource part being at high role here as it's often not as well known part of the JID. 

- XMPP stanza - A single unit of communication in XMPP. It is used to send and receive messages, presence information and IQ (info/query) requests. It is usually in the form of an XML document with a root tag and child tags. The root tag is usually a message, presence or IQ tag. The child tags are usually the data that is being sent. Only message tag is relevant here.

- RFC - Request for Comments. A document that describes a protocol or a standard. It is used to define the rules and guidelines for the protocol. It is often used as a reference for developers when implementing the protocol.

- Tigase - An open source XMPP server written in Java. It is used to implement the XMPP protocol and to provide XMPP services. It is often used as a reference implementation for XMPP.

- XML - Extensible Markup Language. A markup language that is used to define the structure of the data. It is often used to define the structure of the data that is being sent over the internet. It is used in XMPP to define the structure of the XMPP tags and the data that is being sent.

- XML parsing - The process of reading and interpreting XML data. It is used to extract the data from the XML document and to validate the structure of the XML document. It is often used in XMPP to extract the data from the XMPP tags and to validate the structure of the XMPP tags.

- XML serialization - The process of converting an object into an XML document. It is used to convert the data into a format that can be sent over the internet. It is often used in XMPP to convert the data into a format that can be sent over the XMPP protocol.

- XML deserialization - The process of converting an XML document into an object. It is used to convert the data into a format that can be used by the application. It is often used in XMPP to convert the data into a format that can be used by the XMPP server or client.

- XML escaping - The process of converting special characters in XML into a format that can be sent over the internet. It is used to convert special characters into a format that can be sent over the XMPP protocol. It is often used in XMPP to convert special characters into a format that can be sent over the XMPP protocol.

- XML attributes - The properties of an XML tag. They are used to define the properties of the XML tag and to define the data that is being sent. They are often used in XMPP to define the properties of the XMPP tags and the data that is being sent.



## Background
The company example.com wanted to allow users to send messages to each other without sharing their real usernames/JIDs. Their solution was to use ```<alias-sender></alias-sender>``` tag with seemingly random 52 character, lowercase alphanumeric string as the value of the tag. The server would then parse the tag and change the contents of from="" attribute in the message, hiding the real username/JID of the sender.


## Problem
So the developers at example.com validated that the value of the ```<alias-sender></alias-sender>``` tag was a 52 character, lowercase alphanumeric string. They also validated that the JID was valid and that the domain was example.com. After this they placed the value of the ```<alias-sender></alias-sender>``` tag in the from="" attribute of the message. I can only guess what their actual code looked like but I would assume it was something like this:
```python
import re
import xml.etree.ElementTree as ET

def valid_node(node: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]{52}", node))

def valid_domain(domain: str) -> bool:
    return domain == "example.com"

def valid_jid(jid: str) -> bool:
    match = re.fullmatch(r"([a-z0-9]{52})@([a-zA-Z0-9.-]+)(?:/(.+))?", jid)
    if not match:
        return False
    node, domain = match.group(1), match.group(2)
    return valid_node(node) and valid_domain(domain)

mock_stanza = (
    '<message>'
    '<body>Hello, world!</body>'
    '<alias-sender>abcdefghijklmnopqrstuvwxyz0123456789abcdef012345abde@'  
    'example.com</alias-sender>'
    '</message>'
)
msg = ET.fromstring(mock_stanza)
alias = msg.find('alias-sender').text or ''
if not valid_jid(alias):
    raise ValueError('Invalid JID')
if msg.find('body') is not None:
    msg.set('from', alias)
print(ET.tostring(msg, encoding='unicode'))
```
This code is a simplified version of what I think the developers at example.com did. The problem with this code is that it does not validate the resource part of the JID. I assume the developers simply did not know that they would also need to validate the resource part as they do not use it for anything in this context. Their solution would have been fine if they had understood the XMPP RFC thoroughly or if they had reconstructed the jid from their parsed parts, they likely did not do this as it would have made the code less clean and performant. Highlighting the potential issues with over focusing on clean code especially when it comes to high risk parts of the code. 
Here is example that reconstructs the JID from the parsed parts:
```python
import re
import xml.etree.ElementTree as ET

def valid_node(node: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]{52}", node))

def valid_domain(domain: str) -> bool:
    return domain == "example.com"

def validate_and_return_jid(jid: str) -> bool:
    match = re.fullmatch(r"([a-z0-9]{52})@([a-zA-Z0-9.-]+)(?:/(.+))?", jid)
    if not match:
        return False
    node, domain = match.group(1), match.group(2)
    return valid_node(node) and valid_domain(domain),f"{node}@{domain}"

mock_stanza = (
    '<message>'
    '<body>Hello, world!</body>'
    '<alias-sender>abcdefghijklmnopqrstuvwxyz0123456789abcdef012345abde@'  
    'example.com</alias-sender>'
    '</message>'
)
msg = ET.fromstring(mock_stanza)
alias = msg.find('alias-sender').text or ''
is_valid,alias_value = validate_and_return_jid(alias)
if not is_valid:
    raise ValueError('Invalid JID')
if msg.find('body') is not None:
    msg.set('from', alias_value)
print(ET.tostring(msg, encoding='unicode'))
```
 - Note: These examples are in python for simplicity, while the developers at example.com used tigase which is written in java, python's xml.etree.ElementTree actually escapes the given attributes itself so the vulnerability as shown in next chapter would not be possible in this case. Tigase however relies on the developer to do the escaping themselves which caused the vulnerability. 


## Effects of the vulnerability

So because the resource part of the JID was not validated, an attacker could send a message with ```<alias-sender></alias-sender>``` tag with a value of ```aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com/" from="admin@example.com```. This would cause the server to parse the tag and set the from="" attribute with its value resulting in the following message: 
<code><span style="color:#42f572;">&lt;message from="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com</span><span style="color: #f54e42;">/" from="admin@example.com</span><span style="color:#42f572;">"&gt;</span></code>


In the green is the typical from value as expected and in red the part that is unintentionally slid there past any validation thanks to the resource not being validated correctly. Now you can see that there are 2 from attributes in the message one with value of ```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com/``` and one with value of ```
admin@example.com```. 


The server would deserialize this into a string and at some point in the process the first from would be cut off as it is deemed redundant, since stanzas aren't really meant to have 2 same attributes. Client would just see that the sender is admin@example.com. This is already bad enough with attacker being able to impersonate absolutely anyone at will, but this can be taken even further.

The attacker could send a message with ```<alias-sender></alias-sender>``` tag with a value of ```aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com/" from="admin@example.com" a=``` along with extraneous attribute in message tag. This is what the whole stanza would look like:
<code><span style="color:#42f572;">&lt;message</span><span style="color: #f54e42;"> aaaaaaaaaaaaaa="&gt;&lt;sysmsg&gt;this is system message&lt;/sysmsg&gt;&lt;/message&gt;"</span><span style="color:#42f572;">&gt;&lt;body&gt;hello&lt;/body&lt;alias-sender&gt;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com</span><span style="color: #f54e42;">/" from="admin@example.com" a=</span><span style="color:#42f572;">&lt;/alias-sender&gt;&lt;/message&gt;</span></code>
This would cause the server to parse the alias-sender tag and set the from="" attribute with its value resulting in the following message:
```xml
<message from="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com/" 
from="admin@example.com" a="aaaaaaaaaaaaaa=">
<sysmsg>this is system message</sysmsg></message>">
<body>hello</body>
</message>
```
The server would then deserialize this cut off the first from attribute same way as before, add its own internal attributes to it and send it to another server/service that would then cut off any extra parts from the stanza as it is currently not valid XML. This would result it being sent to the client as:
```xml
<message from="admin@example.com" a="aaaaaaaaaaaaaa=">
<sysmsg>this is system message</sysmsg>
</message>
```	
Now our funny little party trick of being impersonate any user is much more serious vulnerability, allowing attacker to send practically any XML tags even ones only meant to be sent by server or bots and not real clients. And this all is because the developers at example.com lacked perfect understanding of what they were parsing. Even after this it could have been saved if they had simply created a new JID object from the parsed parts and used that instead of the raw string. This would have made the code a bit less clean but would have saved them from this vulnerability. 


You might be wondering why our mock attribute is really long, that is because we need it to be after the from attributes for our exploit to work and many XMPP servers actually sort the attributes using some sort of logic, in this case example.com developers sorted them by length, this and many other intricate details are not relevant to the main story here but I thought it would be interesting to mention. 

It is also important to note that I left many smaller details out of this post to keep it simpler to understand and as they are not that interesting in my opinion.

## Conclusion
Always understand whatever you are parsing perfectly and be confident that you understand everything of it, never rely on assumptions that libraries will sanitize input for you without checking if they actually do so in any adequate way. 

Also always reconstruct the object from the parsed parts instead of passing the user input directly, especially if it is a high risk part of your application. The last part also applies even if you feel like you understand what is being parsed perfectly as there is always a chance that you are wrong also there are language and implementation specific differences in parsing. This is due to RFCs not being clear about all edge cases or using words like "should" and "may" which are often interpreted differently by different developers. I will possibly be discussing these differences further in future blog posts.

## Postscript
If this or any other post makes you appreciate my thought process, problem solving skills or understanding of how various things work please hire me.