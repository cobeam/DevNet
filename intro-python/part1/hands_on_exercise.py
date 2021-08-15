"""Intro to Python - Part 1 - Hands-On Exercise."""


import math
import random


# TODO: Write a print statement that displays both the type and value of `pi`
pi = math.pi
print ("Pi =", pi)
print ("The type is", type(pi))


# TODO: Write a conditional to print out if `i` is less than or greater than 50
i = random.randint(0, 100)
print("I is a random number = ", i)
if(i < 50):
	print(i)
elif(i > 50):
	print(i)


# TODO: Write a conditional that prints the color of the picked fruit
picked_fruit = random.choice(['orange', 'strawberry', 'banana'])
if(picked_fruit == "orange"):
	color = "orange"
elif(picked_fruit == "strawberry"):
	color = "red"
else:
	color = "yellow"
print("Random fruit = ", picked_fruit)
print("Colo of random fruit: ", color)
# TODO: Write a function that multiplies two numbers and returns the result
# Define the function here.
def myFun(num1, num2):
	result = num1 * num2
	return result


# TODO: Now call the function a few times to calculate the following answers

print("\n12 x 96 =", myFun(12, 96))

print("48 x 17 =", myFun(48, 17))

print("196523 x 87323 =", myFun(196523,87323))




