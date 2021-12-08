import requests
from bs4 import BeautifulSoup
import json
import pandas
from datetime import date
import twint
import datetime
from datetime import date
from datetime import timedelta
import pandas as pd
import json
import re
import requests
import mysql.connector
from pathlib import Path
from dotenv import load_dotenv
env_path=Path('.')/ '.env'
load_dotenv(dotenv_path=env_path)
import os
today = date.today()
def CVEnew(datas):                          #function to get the tweet data from twitter channel CVEnew
    # configuration
    today = date.today()
    # Yesterday date
    yesterday = today - timedelta(days=1)
    data2 = []
    # check if file exists
    if os.path.exists("data.csv"):          #Condition to remove the existing data 
        os.remove("data.csv")
    config = twint.Config()
    config.Username = "CVEnew"
    config.Store_csv = True
    config.Limit = 100
    config.Output = "data.csv"
    config.Since = str(yesterday)
    #config.Until = str(today)
    # running search
    twint.run.Search(config)
    myfile = Path("./data.csv")
    web_hook_url = os.environ['webhook_url']  # webhook url
    if myfile.is_file():
     df_state = pd.read_csv("data.csv")
    #print("UNIQUE")
     x = df_state['tweet'].unique()
     lister = x.tolist()
     test=[]
     Heap_test = "Heap"
     data3=[]
     strings = "No New Vulnerability Found"
     for i in range(len(lister)):
        for j in range(len(datas)):
            if str(datas[j]) in lister[i]:
                data2.append(lister[i])
                data3.append(datas[j])
     tester3=[]
     for elem in data2:
        if str(Heap_test) in elem:
            data2.remove(elem)
     y = '\n'.join(str(e) for e in data2)
     if len(y) == 0:
        result = "\n{}".format( strings)
     else:
        for i in range(len(data2)):
            for j in range(len(datas)):
                if str(datas[j]) in data2[i]:
                  mydb = mysql.connector.connect(        
                        host="{host name}",       #replace the mysql host name
                        user="{username}",        #replace the mysql user name
                        password="{password}",    #replace password of db
                        database="{db_name}"      #replace dbname
                    )

                  mycursor = mydb.cursor()
                  sql = "INSERT INTO {Table Name} (Date,source,software,cve,description) VALUES (%s,%s,%s, %s, %s)"
                  source="CVE_NEW"
                  CVE=re.findall(r'CVE-\d+-\d+',data2[i])
                  DESCRIPTION=re.findall(r'(?<=\d{4}\s).*',data2[i])
                  datass="\bSoftware:{}\nCve:{}\nDescription:{}".format(datas[j],CVE[0],DESCRIPTION[0])
                  test_Data = (today,source,datas[j], tester[0], tester1[0])
                  mycursor.execute(sql, test_Data)
                  mydb.commit()
                  tester3.append(datass)
        y = '\n'.join(str(e) for e in tester3)
     web_hook_url = os.environ['web_hook_url']  # webhook ur
    #slack_msg = {'text':result }
     slack_msg={
      "username":"CVE_Bot",
      "icon_emoji":":zap:",
      "attachments":[
       {
         "color":"#7bf538",
         "fields":[
            {
               "title":"Source-->Twitter:",
               "value":y
            }
         ]
        }
        ]
        }
     requests.post(web_hook_url, data=json.dumps(slack_msg))

def ibmx(datas):                #Function to get the CVE data from IBMX api 
 headers_dict = {"Accept": "application/json","Authorization":"Basic {API Token}"}
 response = requests.get("https://api.xforce.ibmcloud.com/vulnerabilities/", headers=headers_dict)
 test2=response.text
 y=json.loads(test2)
 apps=[]
 length=len(y)
 test_Data=[]
 strings2="No New vulnerability"
 for i in range(length):
    for j in range(len(datas)):
     if str(datas[j]) in y[i]["platforms_affected"][0]:
        match_data = re.findall(r'stdcode', str(y[i]))
        print("DATA is :{}".format(y[i]))
        mydb = mysql.connector.connect(
            host="{DB host name}", #replace mysql db host
            user="{DB user name }", #replace mysql db username
            password="{DB password}",#replace mysql db password
            database="{DB name}" #Database name wants to save data
        )

        mycursor = mydb.cursor()

        sql = "INSERT INTO {DB } (Date,source,software,cve,description) VALUES (%s,%s,%s, %s, %s)"
        source="IBMX"
        if len(match_data) > 0:
            data = "Software:{}\nCve:{}\nDescription:{}\n".format(datas[j], y[i]["stdcode"][0],y[i]["description"])
            test_Data=(today,source,datas[j],y[i]["stdcode"][0],y[i]["description"])
            mycursor.execute(sql, test_Data)
            mydb.commit()
            apps.append(data)
        else:
            data = "Software:{}\nDescription:{}\n".format(datas[j], y[i]["description"])
            test_Data=(today,source,datas[j], "Null", y[i]["description"])
            mycursor.execute(sql, test_Data)
            mydb.commit()
            apps.append(data)

 y = '\n'.join(str(e) for e in apps)
 if len(y) == 0:
        result = "\n{}".format( strings2)
 else:
        result = "\n{}".format(y)
 web_hook_url = os.environ['webhook_url']
 #slack_msg = {'text': data}
 slack_msg = {
     "username": "CVE_Bot",
     "icon_emoji": ":zap:",
     "attachments": [
         {
             "color": "#7bf538",
             "fields": [
                 {
                     "title": "Source-->IBMX:",
                     "value": result
                 }
             ]
         }
     ]
 }
 requests.post(web_hook_url, data=json.dumps(slack_msg))
def CVE_STALKER(datas):
 # Site URL
 url="https://www.cvestalker.com/daily.php"

 # Make a GET request to fetch the raw HTML content
 html_content = requests.get(url).text

 # Parse HTML code for the entire site
 soup = BeautifulSoup(html_content, "lxml")
 #print(soup.prettify()) # print the parsed data of html
 # On site there are 3 tables with the class "wikitable"
 # The following line will generate a list of HTML content for each table
 gdp = soup.find_all("table", attrs={"class": "w3-table w3-table-all"})
 print("Number of tables on site: ",len(gdp))
 # Lets go ahead and scrape first table with HTML code gdp[0]
 table1 = gdp[0]
 # the head will form our column names
 body = table1.find_all("tr")
 # Head values (Column names) are the first items of the body list
 head = body[0] # 0th item is the header row
 body_rows = body[1:] # All other items becomes the rest of the rows

 # Lets now iterate through the head HTML code and make list of clean headings

 # Declare empty list to keep Columns names
 headings = []
 for item in head.find_all("th"): # loop through all th elements
     # convert the th elements to text and strip "\n"
     item = (item.text).rstrip("\n")
     # append the clean column name to headings
     headings.append(item)
 #print(headings)
 # Next is now to loop though the rest of the rows

 #print(body_rows[0])
 all_rows = [] # will be a list for list for all rows
 for row_num in range(len(body_rows)): # A row at a time
     row = [] # this will old entries for one row
     for row_item in body_rows[row_num].find_all("td"): #loop through all row entries
         # row_item.text removes the tags from the entries
         # the following regex is to remove \xa0 and \n and comma from row_item.text
         # xa0 encodes the flag, \n is the newline and comma separates thousands in numbers
         aa = re.sub("(\xa0)|(\n)|,","",row_item.text)
         #append aa to row - note one row entry is being appended
         row.append(aa)
     # append one row to all_rows
     all_rows.append(row)
 # We can now use the data on all_rowsa and headings to make a table
 # all_rows becomes our data and headings the column names
 df = pandas.DataFrame(data=all_rows,columns=headings)
 dff=df.drop(labels=["HEAT SCORE","RANK(yesterday)"],axis=1)
 lister=dff.values.tolist()
 tester3=[]
 strings = "No New Vulnerability Found"
 for j in range(len(lister)):
  for z in range(len(datas)):
     if str(datas[z]) in str(lister[j]):
         #print("the lister item is :{}".format(lister[j]))
         mydb = mysql.connector.connect(
             host="{Mysql DB host}",
             user="{Mysql DB user}",
             password="{DB password}",
             database="{DB name}"
         )

         mycursor = mydb.cursor()
         sql = "INSERT INTO {Table Name} (Date,source,software,cve,description) VALUES (%s,%s,%s, %s, %s)"
         source="CVE_STALKER"
         cve=re.findall(r'CVE-\d+-\d+',str(lister[j]))
         description=re.findall(r"(?<=\d{4}',\s').*(?='\])",str(lister[j]))
         datass = "Software:{}\nCve:{}\nDescription:{}".format(datas[z], cve[0], description[0])
         test_Data = (today,source,datas[z], cve[0], description[0])
         mycursor.execute(sql, test_Data)
         mydb.commit()
         tester3.append(datass)
 y = '\n'.join(str(e) for e in tester3)
 if len(y) == 0:
        result = "\n{}".format(strings)
 else:
     result = "\n{}".format(y)
 web_hook_url = os.environ['webhook_url']  # webhook url
 slack_msg = {
     "username": "CVE_Bot",
     "icon_emoji": ":zap:",
     "attachments": [
         {
             "color": "#7bf538",
             "fields": [
                 {
                     "title": "Source-->CVE_Stalker(Trending CVE):",
                     "value": result
                 }
             ]
         }
     ]
 }
 requests.post(web_hook_url, data=json.dumps(slack_msg))
def security_database(datas):         #Function to scrape the data from security database.com site
 lister=[]
 x=3
 all_rows=[]
 headings=[]
 for i in range(x):
   y=i+1
   url="https://www.security-database.com/view-all.php?page={}&type=cve".format(y)

   # Make a GET request to fetch the raw HTML content
   html_content = requests.get(url).text

   # Parse HTML code for the entire site
   soup = BeautifulSoup(html_content, "lxml")
 #print(soup.prettify()) # print the parsed data of html
 # On site there are 3 tables with the class "wikitable"
 # The following line will generate a list of HTML content for each table
   gdp = soup.find_all("table", attrs={"class": "alerts_listing full"})
   print("Number of tables on site: ",len(gdp))
 # Lets go ahead and scrape first table with HTML code gdp[0]
   table1 = gdp[0]
 # the head will form our column names
   body = table1.find_all("tr")
 # Head values (Column names) are the first items of the body list
   head = body[0] # 0th item is the header row
   body_rows = body[1:] # All other items becomes the rest of the rows

 # Lets now iterate through the head HTML code and make list of clean headings

 # Declare empty list to keep Columns names
   #headings = []
   for item in head.find_all("th"): # loop through all th elements
     # convert the th elements to text and strip "\n"
     item = (item.text).rstrip("\n")
     # append the clean column name to headings
     headings.append(item)
 #print(headings)
 # Next is now to loop though the rest of the rows

 #print(body_rows[0])
   #all_rows = [] # will be a list for list for all rows
   for row_num in range(len(body_rows)): # A row at a time
     row = [] # this will old entries for one row
     for row_item in body_rows[row_num].find_all("td"): #loop through all row entries
         # row_item.text removes the tags from the entries
         # the following regex is to remove \xa0 and \n and comma from row_item.text
         # xa0 encodes the flag, \n is the newline and comma separates thousands in numbers
         aa = re.sub("(\xa0)|(\n)|,","",row_item.text)
         #append aa to row - note one row entry is being appended
         row.append(aa)
     # append one row to all_rows
     all_rows.append(row)
 # We can now use the data on all_rowsa and headings to make a table
 # all_rows becomes our data and headings the column names
 res=[]
 for i in headings:
     if i not in res:
         res.append(i)
 df = pandas.DataFrame(data=all_rows,columns=res)
 length=len(df)
 tester3=[]
 for j in range(len(df)):
      for z in range(len(datas)):
          if str(datas[z]) in str(df.loc[j,"DETAIL"]):
              mydb = mysql.connector.connect(
                  host="{DB host}",
                  user="{DB user}",
                  password="{DB password}",
                  database="{DB name}"
              )

              mycursor = mydb.cursor()
              sql = "INSERT INTO {replace Tablename} (Date,source,software,cve,description) VALUES (%s,%s,%s, %s, %s)"
              source = "Security-Databse"
              cve = re.findall(r'CVE-\d+-\d+', str(df.loc[j,'NAME']))
              description = re.findall(r"[\w\s\.\#'\(\)]+", str(df.loc[j,'DETAIL']))
              datass = "Software:{}\nCve:{}\nDescription:{}".format(datas[z], cve[0], description[0])
              test_Data = (today, source, datas[z],cve[0], description[0])
              mycursor.execute(sql, test_Data)
              mydb.commit()
              tester3.append(datass)
 strings = "No new vulnerability found"
 y = '\n'.join(str(e) for e in tester3)
 if len(y) == 0:
        result = "\n{}".format(strings)
 else:
     result = "\n{}".format(y)
 web_hook_url = os.environ['webhook_url']  # webhook ur
 # slack_msg = {'text':result }
 slack_msg = {
     "username": "CVE_Bot",
     "icon_emoji": ":zap:",
     "attachments": [
         {
             "color": "#7bf538",
             "fields": [
                 {
                     "title": "Source-->Security-Database:",
                     "value": result
                 }
             ]
         }
     ]
  }
 requests.post(web_hook_url, data=json.dumps(slack_msg))
if __name__ == "__main__":
    data=pandas.read_csv("test.csv")   #Software lists 
    software=data["Software Name"].tolist()
    CVEnew(software)
    ibmx(software)
    CVE_STALKER(software)
    security_database(software)
