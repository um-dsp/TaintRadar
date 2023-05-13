package com.rockthejvm

class Basics extends App{
  //defining values:
  val meaningOfLife: Int = 42
  val aBoolean = false
  val aString = "Hello World"
  val aComposedString = aString + " !"
  val anInterpolatedString = s"$aString !"

  // expressions: structures that can be reduced to values
  val anExpression = 2 + 3
  val ifExpression = if(meaningOfLife>43) 96 else 69

  //code blocks
  val aCodeBlock = {
    val aLocalValue = 67
    //value of block is the value of the last expression
    aLocalValue + 3
  }

  //functions
  def myFunction(x:Int, y:String): String = y + " " + x

  //recursive functions
  def factorial(n: Int): Int = {
    if (n<=1) 1
    else n * factorial(n-1)
  }
  // In scala we don't use loops or iteration, we use RECURSION

  //the unit type: no meaningful value => "void" (type of side effects)
  def myUnitReturningFunction(): Unit = {
    println("Something")
  } //doesn't return anything
  val theUnit = ()
}
