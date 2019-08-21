import com.kinggrid.pdf.KGPdfHummer;
import org.junit.Test;

import java.io.*;

/**
 * Created by Neaium on 2019/8/19.
 *
 * @author Neaium
 */

public class signature {
@Test
   public  void createSignature(String fileName, byte[] ownerPassword,
                                               boolean partial, OutputStream os, File tmpDic, boolean append) throws FileNotFoundException {

        FileOutputStream fileOutputStream = new FileOutputStream("G:/印章子系统/test2.pdf");
    createSignature("G:/印章子系统/test.pdf", null,
            true, fileOutputStream, new File("G:/印章子系统/"),true);


}



}
