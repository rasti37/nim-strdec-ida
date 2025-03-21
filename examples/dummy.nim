import math, os, strenc

const asciiBanner = """
   _   _  ___  __  __
  | \ | |/ _ \|  \/  |
  |  \| | | | | |\/| |
  | |\  | |_| | |  | |
  |_| \_|\___/|_|  |_|
   A demonstration in Nim
"""

proc greetUser(name: string) =
  echo "Hello, " & name & "! Welcome to our Nim demonstration."

proc countVowels(strData: string): int =
  var count = 0
  for ch in strData:
    if ch in ['a', 'e', 'i', 'o', 'u']:
      inc(count)
  return count


proc buildStory(hero: string, place: string): string =
  let part1 = "Once upon a time, in a faraway land called " & place & ", "
  let part2 = "there lived a brave hero named " & hero & ". "
  let part3 = "Each day, " & hero & " wandered the streets of " & place & " seeking adventure."
  let part4 = "\n\nThe townsfolk would whisper: \"" & hero & " is the greatest hero we've ever known!\""
  let conclusion = "\n\nAnd that, dear reader, is how legends are born."
  result = part1 & part2 & part3 & part4 & conclusion

proc getUserNameFromArgs(): string =
  if paramCount() >= 1:
    return paramStr(1)
  else:
    return "NimUser"

proc showcaseMathOps(x: float, y: float) =
  echo "----- Math Operations -----"
  echo "Given x = ", $x, " and y = ", $y
  echo "x + y = ", $(x + y)
  echo "x - y = ", $(x - y)
  echo "x * y = ", $(x * y)
  echo "x / y = ", $(x / y)
  echo "x^2 = ", $(x*x)
  echo "floor(x / y) = ", $floor(x / y)
  echo "ceil(x / y) = ", $ceil(x / y)
  echo "---------------------------"

proc randomQuote() =

  let quotes = [
    "The journey of a thousand miles begins with a single step.",
    "To be or not to be, that is the question.",
    "Fortune favors the bold.",
    "Nothing is impossible to a willing heart.",
    "Hitch your wagon to a star."
  ]

  var idx = int(1337) mod quotes.len
  if idx < 0:
    idx = -idx

  echo "Random Quote of the Run:"
  echo quotes[idx]


when isMainModule:
  echo asciiBanner
  
  let userName = getUserNameFromArgs()
  greetUser(userName)
  
  let story = buildStory("Aster", "Fooville")
  echo "\n--- Short Story ---"
  echo story
  echo "\n-------------------"
  
  showcaseMathOps(42.5, 7.2)
  
  let sampleString = "Nim is Awesome!"
  echo "\nOriginal: \"", sampleString, "\""
  echo "Number of vowels in original string: ", countVowels(sampleString)

  randomQuote()

  echo "\nThanks for running this Nim demonstration, \"", userName, "\"!"
  echo "Feel free to explore, modify, and have fun with Nim."