package sign

import (
	"strconv"
)

func (context *SignContext) createInfo() (info string, err error) {
	original_info := context.PDFReader.Trailer().Key("Info")
	info = strconv.Itoa(int(context.InfoData.ObjectId)) + " 0 obj\n"
	info += "<<"

	info_keys := original_info.Keys()
	for _, key := range info_keys {
		info += "/" + key
		if key == "ModDate" {
			info += pdfDateTime(context.SignData.Signature.Info.Date)
		} else {
			info += pdfString(original_info.Key(key).RawString())
		}
	}

	info += ">>"
	info += "\nendobj\n"
	return info, nil
}
