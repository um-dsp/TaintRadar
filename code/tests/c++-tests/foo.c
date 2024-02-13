void foo()
{
  int x = source();
  if (x < MAX)
  { 
    int y = 2 * x;
    sink(y);
  }
}