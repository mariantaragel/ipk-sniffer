all: build publish

build:
	dotnet build ipk-sniffer/ipk-sniffer.csproj

publish:
	dotnet publish ipk-sniffer/ipk-sniffer.csproj -c Release -o .

clean:
	rm -r ipk-sniffer/bin
	rm -r ipk-sniffer/obj
	rm ipk-sniffer
	rm *.pdb
