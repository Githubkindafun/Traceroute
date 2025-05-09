CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
TARGET = traceroute
SRC = main.cpp
OBJ = main.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)

distclean: clean
	rm -f $(TARGET)
