#intrusion detection alarm design pseudocode
function IDS(GivenTimePeriod, Thres_Occurences)
#read auth.log file in a given period as FAILLOG
#Fisrtly, we initiate an empty dictionary set D for 
#recording pair {uid, count} as D{key,value} in the following steps
	D={}
	#Then, we choose the useful part in the log according to the time set period
		for each line L in FAILLOG:
			if CurrentTime-L.DateAndTime<GivenTimePeriod:
			#according to the time limit, we choose the efficient uid, 
			#as D[key]=uid
			#and set its initial count with 1, from which D[value]=1 
			#representing one occurrence
				D={L.uid,1}
			end if
		end for

		#loop session
		len = D.length
		while (true):
			for i in range(1,len):
				#Groupby uid and add the value in a certain time period
				D[value]=D[value].groupby(D[key])
				#sum the value according to uid
				for j in D[value]:
					#if the value is more than we expect, 
					#it is suspicious of Brute Force Vulnerability
					if j> Thres_Occurences:
						ALARM!
						return D
					else
						continue

					end if
				end for 
			end for 
		end while 
end function



