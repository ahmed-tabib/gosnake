package main

import (
	"fmt"

	"automation.com/cachesnake"
)

func main() {
	a := cachesnake.HeaderBinarySearchArgs{}
	s := cachesnake.HeaderBinarySearch(&a)

	fmt.Println(s)
}
