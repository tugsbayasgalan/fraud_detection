Instructions to run the program:

1) Run pip install ipinfo and get an access token from the ipinfo website
2) Run python fraud_ip_detection.py -f [FILEPATH] -a [ACCESS_TOKEN]
3) Input the ip address on the command prompt



Follow Up Questions:
1) What circumstances may lead to false positives or false negatives when using solely this score?\n
Current assumption is that longer the distance is, higher the probability that the ip address is fraud.
This will lead to some false positives because we are assuming any ip address that are close to a fraud ip address as fraud.
This will lead to some false negatives because if a non-fraud ip address that is very far away from our previous ip addresses, it will likely be classified as fraud. From above two, we can see that the distance as a sole metric for fraud detection is not complete.
We have to take into account many different factors.\n

2) What challenges are there with computing distances based on latitude/longitude?\n
As the number of supplied ip addresses increase, the complexity of our program increases in a linear fashion. Therefore we might need
to implement some filters to reduce number of comparisons.

Further Considerations:
1) Right now, we are not learning anything from user inputs because we just assign scores to them and not use them as data points.
Therefore the accuracy will remain same even after running the program for long time. We need a way to use online inputs as our data points.

2) As discussed in follow up questions, we need to come up with different metrics to detect fraud detection.

3) Ideally, we can parallelize the API calls to ipinfo in the setup phase.

4) Better error handling (input error, bad input etc) 
