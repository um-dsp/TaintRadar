package com.rockthejvm

object FunctionalProgramming extends App{
  // Scala is OO
  class Person(name: String) {
    def apply(age: Int) = println(s"I have aged $age years")
  }
  val bob = new Person("Bob")
  bob.apply(43)
  bob(43) // invoking bob as a function -> bob.apply(43)

  /*
  Scala runs on JVM: Object first-class citizen
  Functional programming: functions first-class citizen
  -> compose functions
  -> pass functions as args
  -> return functions as results
  ==> FunctionX
   */

  val simpleIncrementer = new Function1[Int, Int] {
    override def apply(arg: Int): Int = arg + 1
  }
  simpleIncrementer.apply(23) // 24
  simpleIncrementer(23) // 24
  // defined a function

  // All scala functions are instances of these Function_X types
  // function with 2 arguments and a String return type
  val stringConcatenator = new Function2[String, String, String] {
    override def apply(arg1: String, arg2: String): String = arg1 + arg2
  }
  stringConcatenator("I love ", "Scala") // "I love Scala"

  //syntax sugars
  val doubler1: Function1[Int, Int] = (x: Int) => 2 * x // shorthand for defining apply function
  val doubler2: Int => Int = (x: Int) => 2 * x // shorthand for above
  val doubler3 = (x: Int) => 2 * x // shorthand for above
  doubler1(4) // 8

  // higher order functions: take functions as arguments / return functions as results
  val aMappedList: List[Int] = List(1,2,3).map(x => x+1)
  println(aMappedList)
  val aFlatMappedList = List(1,2,3).flatMap(x => List(x, 2*x))
  val aFlatMappedList2 = List(1,2,3).flatMap{ x =>
    List(x, 2*x)
  } // alternative to the above
  val aFilteredList = List(1,2,3,4,5).filter(x => x <= 3)
  val aFilteredList2 = List(1,2,3,4,5).filter(_ <= 3)

  // all pairs between 1,2,3 and a,b,c
  val allPairs = List(1,2,3).flatMap(number => List('a', 'b', 'c').map(letter => s"$number-$letter"))

  // for comprehensions
  val alternativePairs = for {
    number <- List(1,2,3)
    letter <- List('a', 'b', 'c')
  } yield s"$number-$letter"
  // equivalent to the map/flatmap chain above

  // lists
  val aList = List(1,2,3,4)
  val firsElement = aList.head
  val rest = aList.tail
  val aPrependedList = 0 :: aList // List(0,1,2,3,4,5)
  val anExtendedList = 0 +: aList :+ 6 // List(0,1,2,3,4,5,6)

  // sequences
  val aSequence: Seq[Int] = Seq(1,2,3) // Seq.apply(1,2,3)
  val accessedElement = aSequence(1) // the element at index 1: 2

  // vectors: fast Seq implementation
  val aVector = Vector(1,2,3,4,5)

  // sets: no duplicates
  val aSet = Set(1,2,3,1,2,3) // Set(1,2,3)
  val setHas5 = aSet.contains(5)
  val anAddedSet = aSet + 5
  val aRemovedSet = aSet - 3

  // ranges
  val aRange = 1 to 1000
  val twoByTwo = aRange.map (x => 2*x).toList

  // tuples: groups of values under the same value
  val aTuple = ("Elie", "Rizk", 21)

  // maps
  val aPhoneBook: Map[String, Int] = Map(
    ("Daniel", 12332),
    "Jane" -> 876234 // ("Jane", 876234)
  )
}
