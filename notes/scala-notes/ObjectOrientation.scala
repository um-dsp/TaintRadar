package com.rockthejvm

object ObjectOrientation extends App {
  // java equivalent: public static void main(String[] args)

  // class and instance
  class Animal {
    val age: Int = 0
    def eat() = println("I'm eating")
  }
  val anAnimal = new Animal

  //inheritance
  class Dog(val name: String) extends Animal //constructor definition
  val aDog = new Dog("Roxy")
  //constructor arguments are not fields (need to put a val for that)
  aDog.name

  //subtype polymorphism
  val aDeclaredAnimal: Animal = new Dog("Hachi")
  aDeclaredAnimal.eat() //most derived method will be called at runtime

  //abstract class
  abstract class WalkingAnimal {
    val hasLegs = true //by default public, can restrict with private or protected
    def walk(): Unit
  }

  //interface: ultimate abstract type
  trait Carnivore {
    def eat(animal: Animal): Unit
  }

  trait Philosopher {
    def ?!(thought: String): Unit
  }
  //single-class inheritance, multi-trait "mixing"
  class Crocodile extends Animal with Carnivore with Philosopher {
    override def eat(animal: Animal): Unit = println("I am eating you")
    override def ?!(thought: String): Unit = println(s"I was thinking $thought")
  }

  val aCroc = new Crocodile
  aCroc.eat(aDog)
  aCroc eat aDog //infix notation = object method argument, only available for methods with one argument
  aCroc ?! "what if we could fly"

  //operators are method
  val x = 1+2
  val y = 1.+(2)

  //anonymous classes => compiler creates an anonymous class for one instance
  val dinosaur = new Carnivore {
    override def eat(animal: Animal): Unit = println("I am a dinosaur so I can eat anything")
  }

  // Singleton object
  object MySingleton { // the only instance of type MySingleton
    val mySpecialValue = 69
    def mySpecialMethod(): Int = 24
    def apply(x: Int): Int = x + 1
  }
  MySingleton.mySpecialMethod()
  MySingleton.apply(68)
  MySingleton(68) // equivalent to the above

  object Animal { // companion object (singleton with existing class)
    // companions can access each other's private fields/methods
    // singleton Animal and instances of Animal are different things
    val canLiveIndefinitely = false
  }
  val animalsCanLiveForever = Animal.canLiveIndefinitely // "static" fields/methods

  /*
   case classes: lightweight data structures with some boilerplate
   the compiler automatically generates the following:
   - sensible equals and hash code
   - serialization
   - companion with apply (returns instance of object)
   - pattern matching
   */
  case class Person(name: String, age: Int)
  // may be constructed without new
  val bob = Person("Bob", 54) //singleton.apply => class instance

  // exceptions
  try{
    val x: String = null
    x.length
  } catch {
    case e: Exception => "some faulty error message"
  } finally{
    // execute some code no matter what
  }

  // generics
  abstract class MyList[T] {
    def head: T
    def tail: MyList[T]
  }

  // using a generic with a concrete type
  val aList: List[Int] = List(1,2,3) // List.apply(1,2,3)
  val first = aList.head
  val rest = aList.tail
  val aStringList = List("hello", "Scala")
  val firstString = aStringList.head

  // #1: in Scala we usually operate with IMMUTABLE values/objects
  // Any modification to an object must return ANOTHER object
  // Good for multithreaded/distributed env, making sense of the code
  val reversedList = aList.reverse // returns a NEW list

  // #2: Scala is closest to the OO ideal (everything is inside an instance of an object)
}
