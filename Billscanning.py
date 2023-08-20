import PyPDF2
from PyPDF2 import PdfReader,PdfWriter
import re
import datetime
from dotenv import load_dotenv

import fitz
import io

user = []

def extract_numbers_from_line(line):
    consumption = []
    temp=[]
    output_cleaned = re.sub(r'\([^()]+\)', '', line).strip()
    numbers = re.findall(r'\d+\.\d+|\d+', output_cleaned)
    for i in numbers:
        temp.append(float(i))
    consumption.append(max(temp))
    return consumption


def scan_pdf_for_keywords(file, keywords):
    #Scan the pdf for the keywords of Senoko to check company, as well as their energy consumption
    #This code already disables javascript execution
    pdf_text = ''
    reader = PdfReader(file)
    senoko = False
    for page in reader.pages:
        pdf_text += page.extract_text()

    lines = pdf_text.split('\n')
    for line in lines:
        if "SENOKO" in line.upper():
            senoko = True
            break
        else:
            senoko = False
    if senoko == True:
        keyword_lines = []
        for line in lines:
            if any(keyword in line for keyword in keywords):
                keyword_lines.append(line)
        numbers = []
        billdate = [line for line in keyword_lines if '- Adjustment' not in line]
        pattern = r'\((.*?)\)'
        date = []
        if len(billdate)<1:
            return 0,0,False
        for line in billdate:
            matches = re.findall(pattern, line)
            date.extend(matches)

        dates = []
        for content in date:
            date_range = content.split(" - ")
            dates.extend(date_range)

        for line in keyword_lines:
            line_numbers = extract_numbers_from_line(line)
            numbers.extend(line_numbers)
        return numbers,dates,True
    else:
        return 0,0,False

def checkdaterange(billdates):
    #Pulls out the current date and year afterwards check if the bill submitted is within the current date and year range
    validation = True
    date_format = "%d %b %Y"
    current_date = datetime.date.today()
    current_month = current_date.month
    current_year=current_date.year
    if current_month >= 2:
        target_month = current_month - 2
        target_year = current_year
    else:
        target_month = current_month + 10
        target_year = current_year - 1
    yearperiod = str(target_year)+'-'+str(current_year)
    month_name1,month_name2 = current_date.replace(month=target_month).strftime('%b'),current_date.replace(month=target_month+1).strftime('%b')
    month_period = str(month_name1) + '-' + str(month_name2) #Current date
    d1, d2 = datetime.datetime.strptime(billdates[0].strip(), date_format), datetime.datetime.strptime(billdates[1].strip(), date_format)
    sorteddates = sorted([d1, d2])

    month1 = sorteddates[0].strftime("%b")
    streak = sorteddates[0].strftime('%m')
    month2 = sorteddates[1].strftime("%b")
    year1,year2 = sorteddates[0].strftime(("%Y")),sorteddates[1].strftime(("%Y"))
    year_period = year1+'-'+year2
    period = month1 + '-' + month2 #Your submission date
    # Checking
    # Commented out for now until I get my hands on later on bills
    if year_period == yearperiod and month_period==period:
        validation = True
    else:
        validation = False
    #Comment this to show bill not in same time period
    if validation == True:
        return period,year_period,True,month_period,streak
    else:
        return period,year_period,False,month_period,streak

def checkcurrentleaderboard():
    date_format = "%d %b %Y"
    current_date = datetime.date.today()
    current_month = current_date.month
    current_year = current_date.year
    if current_month >= 2:
        target_month = current_month - 2
        target_year = current_year
    else:
        target_month = current_month + 10
        target_year = current_year - 1
    yearperiod = str(target_year) + '-' + str(current_year)
    month_name1, month_name2 = current_date.replace(month=target_month).strftime('%b'), current_date.replace(month=target_month + 1).strftime('%b')
    month_period = str(month_name1) + '-' + str(month_name2)
    return yearperiod,month_period
def processdata(data):
    dictionary = {}
    for document in data:
        dictionary[document.id] = document.to_dict()
    return dictionary
def checkbillhistory(submittedmonth,submittedyear,data):
    for item in data:
        if item['Period'] == submittedmonth and item['Year'] == submittedyear:
            return True
    return False

def checkstreak(recent_data,current):
    if int(current) - 1 == 0:
        check = 12
    else:
        check = int(current)
    if check - 1 == recent_data['Streak']:
        return True
    else:
        return False
def energycalc(numbers):
    y = 0
    for i in numbers:
        y += float(i)
    return y

