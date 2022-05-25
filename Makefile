

.PHONY: all
all:
	g++ -O3 -std=c++17 -Wall -o main Main.cxx
	g++ -O3 -std=c++17 -Wall -pthread -o docker Docker.cxx
