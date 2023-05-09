JC = javac
JFLAGS = -d bin -cp bin

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	src/client/Command.java \
	src/myCloud.java \
	src/myCloudServer.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) bin/*.class
