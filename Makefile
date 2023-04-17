all: build publish

build:
	dotnet build src/ipk-sniffer.csproj

publish:
	dotnet publish src/ipk-sniffer.csproj -c Release -o .

tests:
	dotnet build src/ipk-sniffer-tests.csproj

clean:
	rm -r src/bin
	rm -r src/obj
	rm ipk-sniffer
	rm *.pdb
