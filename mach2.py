#Added this c1
import json
import csv
import collections
import os
import random
import pprint
import pandas as pd
from random import choices
import numpy as np
import math

directory =os.path.abspath(r"c:\This one\Research\NVD dataset\JSON\\")
os.chdir(r"C:\This one\Research\NVD dataset\JSON")
file = open(r'c:\This one\Research\NVD dataset\JSON\\nvdcve-1.0-2017.json').read()
data = json.loads(file)
totvul_len= range(1,len(data['CVE_Items']))
pprint.pprint(data['CVE_Items'][-10])
#print(data.keys())

#for key, value in data.items():
 #   print(key)

#l = list(map(lambda x: {key:v for k,v in x.items() if k in totvul_len},data['CVE_Items']))
#print(l)
kk= dict((key,data['CVE_Items'][key]['impact']['baseMetricV3']['cvssV3']['baseScore'])for key in totvul_len if 'baseMetricV3' in data['CVE_Items'][key]['impact'] )
gg= dict((key,data['CVE_Items'][key]['publishedDate']) for key in totvul_len)


pubdatelist=[]
cvsslist=[]
cveidlist=[]

for key, value in gg.items():
    temp= [key,value]
    pubdatelist.append(temp)

for key, value in kk.items():
    temp= [key,value]
    cvsslist.append(temp)



df1= pd.DataFrame(pubdatelist)
df2=pd.DataFrame(cvsslist)


df1.columns= ['CVEno','pubdate']
df2.columns= ['CVEno','CVSS']

mm= df1.merge(df2, on= 'CVEno', how= 'left')
mm.dropna(subset=['CVSS'],inplace= True)
mm['pubdate']= pd.to_datetime(mm['pubdate'])
mm['category']= np.where(mm['CVSS']>=9, "critical",np.where(mm['CVSS']<4, "low",np.where(mm['CVSS']<7, "medium","high")))
mm['SLA']= np.where(mm['category']=="critical",3,np.where(mm['category']=="high",7,np.where(mm['category']=="medium",14,30)))
#mm.to_csv('C:\This one\data2017_1.csv')

# Randomly assign jobtypes
job_population= ['sequential','concurrent']
job_weights= [0.1,0.9]
mm['jobtype']=choices(job_population,job_weights, k= len(mm))

# Randomly assign team times
no_teams=3
team1_time_population= list(range(0,6))
team2_time_population=list(range(0,8))
team3_time_population=list(range(0,4))

team1_time_weights= list(np.repeat(0.166,6))
team2_time_weights= list(np.repeat(1/8,8))
team3_time_weights= list(np.repeat(1/4,4))

mm['team1']= choices(team1_time_population,team1_time_weights,k=len(mm))
mm['team2']= choices(team2_time_population,team2_time_weights,k=len(mm))
mm['team3']= choices(team3_time_population,team3_time_weights,k=len(mm))

mm['totaltime']= mm['team1']+mm['team2']+mm['team3']

mm= mm.replace('\n',' ',regex=True)

print(mm.head(10))

# Create subdataframes for each category of vul
sub1= mm[mm.category == "critical"]
sub2= mm[mm.category == "high"]
sub3= mm[mm.category == "medium"]
sub4= mm[mm.category == "low"]


#Input Distribution
monthlyavg= 1000
dailyavg= math.ceil(monthlyavg/30)
no_days= 10
print("dailyavg is " + str(dailyavg))
sigma= 2
ratios= [0.15,0.50,0.34,0.01]

# Create normal distributions for each category based on ratios above
print(dailyavg*ratios[0])

crtical_norm= np.random.normal(math.ceil(dailyavg*ratios[0]),2,no_days)
high_norm= np.random.normal(math.ceil(dailyavg*ratios[1]),2,no_days)
med_norm= np.random.normal(math.ceil(dailyavg*ratios[2]),2,no_days)
low_norm= np.random.normal(math.ceil(dailyavg*ratios[3]),2,no_days)


#build daily dataframe
critemp= sub1.head(int(crtical_norm[0]))
higtemp = sub2.head(int(high_norm[0]))
medtemp = sub3.head(int(med_norm[0]))
#lowtemp = sub4.head(int(low_norm[0]))
dailydump= pd.concat([critemp,higtemp,medtemp])
print("daily dump is" + str(dailydump.shape))
#Create schedules for Teams

teams= ["team1","team2","team3"]
team1= pd.DataFrame()
team2= pd.DataFrame()
team3= pd.DataFrame()

print(dailydump.head(20))

count=0
for index, row in dailydump.iterrows():
    if row["jobtype"]== "concurrent":
        if row['category'] != "medium" or row['category'] != "low":
            count += 1
            data = str(row["category"]) + str(row["CVEno"])
            if  max(row["team1"],row["team2"],row["team3"])<= row["SLA"]:
                id= str(index+1)
                temp1= pd.DataFrame({id: np.tile([data],row['team1'])})
                team1= pd.concat([team1,temp1],axis=1)

                temp2 = pd.DataFrame({id: np.tile([data], row['team2'])})
                team2 = pd.concat([team2, temp2], axis=1)

                temp3 = pd.DataFrame({id: np.tile([data], row['team3'])})
                team3 = pd.concat([team3, temp3], axis=1)
            else:
                for t in teams:
                    if row[t] > row["SLA"]:
                        if t is "team2":
                            if row['team2']<= 2*row['SLA']:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row[t]-row['SLA'])})
                                team2 = pd.concat([team2, temp1,temp2], axis=1)
                            else:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp3 = pd.DataFrame({id: np.tile([data], row[t]- 2*row['SLA'])})
                                team2 = pd.concat([team2, temp1, temp2,temp3], axis=1)
                        elif t is "team1":
                            if row['team1']<= 2*row['SLA']:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row[t]-row['SLA'])})
                                team1 = pd.concat([team1, temp1,temp2], axis=1)
                            else:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp3 = pd.DataFrame({id: np.tile([data], row[t]- 2*row['SLA'])})
                                team1 = pd.concat([team1, temp1, temp2,temp3], axis=1)
                        else:
                            if row['team3']<= 2*row['SLA']:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row[t]-row['SLA'])})
                                team3 = pd.concat([team3, temp1,temp2], axis=1)
                            else:
                                temp1 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp2 = pd.DataFrame({id: np.tile([data], row['SLA'])})
                                temp3 = pd.DataFrame({id: np.tile([data], row[t]- 2*row['SLA'])})
                                team3 = pd.concat([team3, temp1, temp2,temp3], axis=1)
        team1.fillna(0)
        team2.fillna(0)
        team3.fillna(0)





for i in range(len(team1.columns)):
    team1.rename(columns= {team1.columns[i]: str(i)},inplace= True)

for i in range(1,len(team2.columns)):
    team2.rename(columns= {team2.columns[i]: str(i)}, inplace= True)

for i in range(1,len(team3.columns)):
    team3.rename(columns= {team3.columns[i]: str(i)}, inplace= True)

print(str(len(team1.columns)))
new_names = list(range(1,len(team1.columns)))
print(type(new_names))

print("\nteam 1 is "+ str(team1.shape))
print(team1)
print("\nteam 2 is "+ str(team2.shape))
print(team2)
print("\nteam 3 is "+ str(team3.shape))
print(team3)
print("count is " +str(count))

team1.to_csv('C:\This one\oneteam_1.csv')
team2.to_csv('C:\This one\oneteam_2.csv')
team3.to_csv('C:\This one\oneteam_3.csv')
