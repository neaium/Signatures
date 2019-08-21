package service;

import com.kinggrid.pdf.KGPdfHummer;

import java.io.File;
import java.io.OutputStream;

/**
 * Created by Neaium on 2019/8/20.
 *
 * @author Neaium
 */
public interface CreateSignature {
    public  void createSignature(String fileName, byte[] ownerPassword,
                                              boolean partial, OutputStream os, File tmpDic, boolean append);
}
