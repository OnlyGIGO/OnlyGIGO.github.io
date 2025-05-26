---
title: "Parsing and Validation: Dangerous Differences between programming languages and implementations"
categories: [security]
tags: [security,parsing,validation,RFC,python,golang]
---
## Introduction
RFCs are the backbone of internet standards, and they often define how data should be parsed and validated. However, different programming languages and implementations can interpret these RFCs in various ways, leading to potential security vulnerabilities. This is largely due to RFCs using vague language and words like "should" and "may," which can be interpreted differently by different implementations. 
Sometimes RCFs are way too broad and following them perfectly is simply impossible and/or unrealistic leading to further inconsistencies in how data is parsed and validated.

A good example of this is RFC 5222 which defines the syntax for email addresses. It is so broad that no email provider follows it perfectly. As an example gmail only allows minimum 6 characters for the local part of the email address, while hotmail allows 1 character. Gmail allows local part of the address to start with a number, while hotmail does not.

These issues can lead to inconsistencies in how data is parsed and validated, potentially allowing for security vulnerabilities to be exploited.

In this post, we will explore some of the dangerous differences in parsing and validation across different programming languages and implementations, using examples from Python and Golang.

We will be comparing the differences in specifically XML parsing and validation. We choose this because it is easy to see the differences, it has very real world implications and because this format is quite widely used.

## Terms used in this post

 - XML - Extensible Markup Language, a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable.

 - RFC - Request for Comments, a type of publication from the leading technical development and standards-setting bodies for the internet.

 - Parsing - The process of analyzing a string of symbols, either in natural language or in computer languages, and converting it into a data structure that can be easily manipulated by a program.

 - Validation - The process of checking if the data is in the correct format and meets the requirements defined by the RFC or other standards. Usually also done for security reasons to prevent attacks like XSS, SQL injection, etc.

- Polyglot programming - A programming paradigm that allows for the use of multiple programming languages in a single application or system. This can be done for various reasons, such as leveraging the strengths of different languages or using existing codebases.

- XSS - Cross-Site Scripting, a type of security vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users. This can lead to data theft, session hijacking, and other attacks.

- SQL injection - A type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve, such as other users' data. In some cases, it may even allow an attacker to modify or delete data, causing persistent changes to the application's content or behavior.

- XSD - XML Schema Definition, a way to define the structure and data types of an XML document. It is used to validate the XML document against a set of rules, ensuring that the document is well-formed and adheres to the defined schema.

- XXE - XML External Entity, a type of attack that allows an attacker to interfere with the processing of XML data. This can lead to various attacks, such as file disclosure, server-side request forgery (SSRF), and denial of service (DoS) attacks.

## XML Parsing and Validation
We will start with XML parsing and therefore validation differences between programming languages. We will explore a hypothetical bookstore. That decided to use python backend to handle user authentication, XML parsing and validation, golang as a microservice to then store the data into a database. To save time and effort the bookstore decided to pass XML to golang as well instead of transforming it into JSON or protocol buffers.
Their XML schema for publishing books is as follows:
```xml
<books>
    <book>
        <title>Book Title</title>
        <author>Author Name</author>
        <price>19.99</price>
        <publish_date>2023-01-01</publish_date>
    </book>
</books>
```

The bookstore is very security conscious and went above and beyond to validate the data they receive. They went unrealistically hard on the validation and only allow alphanumeric characters in title of the book with maximum length of 50 characters. They also only allow regular ASCII letters in the author name. The price must be a decimal number and the publish date must be in YYYY-MM-DD format.

Notice that in real world scenario we would be using defusedxml package to prevent XXE attacks and other security issues. **HOWEVER** it would not have prevented the issue we are going to discuss in this post anyway. We are simply not using it to allow readers to run this code more easily incase they want to, as defusedxml is not a standard library and is not installed by default.

Following is the code for parsing and validating the XML in python:
```python
import re
from datetime import datetime
import xml.etree.ElementTree as ET

title_pattern = re.compile(r'^[A-Za-z0-9 ]{1,50}$')
author_pattern = re.compile(r'^[A-Za-z ]+$')


def validate_book_element(book_elem):
    """
    Validate a single <book> ElementTree element.
    Returns a list of error messages (empty if valid).
    """
    errors = []

    # Title: alphanumeric (and spaces), max length 50
    title = book_elem.findtext('title')
    if title is None:
        errors.append("Missing <title> element.")
    elif not title_pattern.fullmatch(title):
        errors.append(f"Invalid title '{title}'. Must be alphanumeric (spaces allowed) and at most 50 characters.")

    # Author: letters only (a-z, A-Z and spaces)
    author = book_elem.findtext('author')
    if author is None:
        errors.append("Missing <author> element.")
    elif not author_pattern.fullmatch(author):
        errors.append(f"Invalid author '{author}'. Must contain letters and spaces only.")

    # Price: valid decimal number
    price = book_elem.findtext('price')
    if price is None:
        errors.append("Missing <price> element.")
    else:
        try:
            float(price)#we are lazy
        except ValueError:
            errors.append(f"Invalid price '{price}'. Must be a valid float.")

    # Publish date: valid date YYYY-MM-DD
    date_text = book_elem.findtext('publish_date')
    if date_text is None:
        errors.append("Missing <publish_date> element.")
    else:
        try:
            datetime.strptime(date_text, '%Y-%m-%d')
        except ValueError:
            errors.append(f"Invalid publish_date '{date_text}'. Must be in YYYY-MM-DD format and a real date.")

    return errors


def validate_books(xml_string):
    """
    Parse the given XML string containing one or more <book> entries
    and validate each. Returns a dict mapping book index to error lists.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}")

    results = {}
    # If root is <book>, wrap in list; else findall
    books = [root] if root.tag == 'book' else root.findall('book')
    for idx, book in enumerate(books, start=1):
        errs = validate_book_element(book)
        if errs:
            results[idx] = errs
    return results


if __name__ == '__main__':
    # Example XML string to validate, it would be coming from http request in the  actual scenario but
    # for the sake of this example we are just using a string.
    sample_xml = '''
    <books>
        <book>
            <title>Book Title</title>
            <author>Author Name</author>
            <price>19.99</price>
            <publish_date>2023-01-01</publish_date>
        </book>
    </books>
    '''
    validation_results = validate_books(sample_xml)
    if validation_results:
        for book_idx, errors in validation_results.items():
            print(f"Errors in book #{book_idx}:")
            for err in errors:
                print(f" - {err}")
    else:
        print("All book entries are valid.")
```


Everything seems to be working fine the validator seemingly catches all the errors in data. You can play with it yourself if you manage to bypass the validation in any meaningful way, but I doubt it as it is pretty robust.


After the validation is done the python backend sends the data to golang microservice which is responsible for storing the data into a database. The golang microservice is also responsible for parsing and validating the XML data, however with less validation as the developers assume only already validated data ever reaches it. The golang code for parsing and validating the XML data is as follows:
```go
package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"strconv"
	"time"
)

// Book represents one <book> element.
type Book struct {
	Title       string    `xml:"title"`
	Author      string    `xml:"author"`
	PriceStr    string    `xml:"price"`
	DateStr     string    `xml:"publish_date"`
	Price       float64   // parsed from PriceStr
	PublishDate time.Time // parsed from DateStr
}

// Books is the container for multiple Book entries.
type Books struct {
	XMLName xml.Name `xml:"books"`
	Books   []Book   `xml:"book"`
}

func main() {
	sampleXML := []byte(`
     <books>
        <book>
            <title>Book Title</title>
            <author>Author Name</author>
            <price>19.99</price>
            <publish_date>2023-01-01</publish_date>
        </book>
    </books>
    `)

	var catalog Books
	if err := xml.Unmarshal(sampleXML, &catalog); err != nil {
		log.Fatalf("Error parsing XML: %v", err)
	}

	for i, b := range catalog.Books {
		// convert price
		p, err := strconv.ParseFloat(b.PriceStr, 64)
		if err != nil {
			log.Printf("Book #%d: invalid price %q: %v", i+1, b.PriceStr, err)
			continue
		}
		// parse date
		d, err := time.Parse("2006-01-02", b.DateStr) //first argument is the layout, second is the value to parse
		if err != nil {
			log.Printf("Book #%d: invalid publish_date %q: %v", i+1, b.DateStr, err)
			continue
		}

		// assign parsed fields
		b.Price = p
		b.PublishDate = d

		// print out
		fmt.Printf("Book #%d:\n", i+1)
		fmt.Printf("Title       : %s\n", b.Title)
		fmt.Printf("Author      : %s\n", b.Author)
		fmt.Printf("Price       : %.2f\n", b.Price)
		fmt.Printf("PublishDate : %s\n\n", b.PublishDate.Format("2006-01-02")) // Go uses a specific date to format time, this is the reference date
        //here we would be storing the data into a database, but for the sake of this example we are just printing it out for simplicity
	}
}
```

We run the code with our example XML and everything seems to be working fine. The data is parsed and validated correctly and the data is in our example printed out correctly:
```text
Book #1:
  Title       : Book Title
  Author      : Author Name
  Price       : 19.99
  PublishDate : 2023-01-01
```
All sorts of invalid dates are quickly caught by the python validator and never reaches the golang microservice. Everything is all fine and good until really clever attacker tries to exploit the system with following XML:
```xml
 <books>
        <book>
            <title>Book Title</title>
            <author>Author Name</author>
            <author>'union select 1,2,3-- -</author>
            <price>19.99</price>
            <publish_date>2023-01-01</publish_date>
        </book>
</books>
```
Our python validator only parses first instance of author tag and doesn't see anything wrong the with XML payload as it never sees the 2nd one. After the data being validated it simply passes the validated XML forward instead of reconstructing it for simplicity, less code and higher performance. Now let's see what our golang thinks about the XML, the program produces following output:
```text
Book #1:
  Title       : Book Title
  Author      : 'union select 1,2,3-- -
  Price       : 19.99
  PublishDate : 2023-01-01
```
Oops for some reason Golang parses last author tag in the XML resulting in potential sql injection if the data is passed to a SQL query without proper sanitization. This is a classic example of how different programming languages and implementations can interpret the same XML data in different ways, leading to potential security vulnerabilities. 

This does not even require microservice the data could be passed directly to client and client's application is simply written in different programming language than the backend or it uses different library and suddenly the data is parsed differently than it was intended. 


## Conclusion
Always be aware of the potential differences in parsing and validation across different programming languages and implementations. This is especially important when dealing with data that will be passed between different systems or components, as the same data may be interpreted differently by different systems. 

Best ways to avoid this are in my experience to either regenerate the data from the validated data which can also protect from other issues or to use XSD schema to validate the XML. 

## Postscript
If this or any other post makes you appreciate my thought process, problem solving skills or understanding of how various things work please hire me.