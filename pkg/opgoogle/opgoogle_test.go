package opgoogle

import (
	"log"
	"testing"
)

func TestGetDoc(t *testing.T) {
	docID := "1HrwVZLRTGiK9ZsKmG8OqsBQdpAr1rCkE9zxOIIOvAgA"

	docSv, err := GetSheetService()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := docSv.Spreadsheets.Values.Get(docID, "sheet1!F2:F").Do()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Values) == 0 {
		log.Println("No data found.")
	} else {
		log.Println("Name:")
		for _, row := range resp.Values {
			// Print columns A and E, which correspond to indices 0 and 4.
			log.Printf("%d %s\n", len(row), row)
		}
	}
}