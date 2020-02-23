/*############################################################################
  # Copyright 2016 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     Internal EC Function Prototypes
// 
// 
*/


/*
// Point Operation Prototypes
// May be varied for different kinf of GP(p)
*/
struct eccp_method_st {
   //void (*CopyPoint)(const IppsECCPPointState* pSrc, IppsECCPPointState* pDst);

    void (*SetPointProjective)(const IppsBigNumState* pX,
                              const IppsBigNumState* pY,
                              const IppsBigNumState* pZ,
                              IppsECCPPointState* pPoint,
                              const IppsECCPState* pECC);
   void (*SetPointAffine)(const IppsBigNumState* pX,
                          const IppsBigNumState* pY,
                          IppsECCPPointState* pPoint,
                          const IppsECCPState* pECC);

   //void (*GetPointProjective)(IppsBigNumState* pX,
   //                           IppsBigNumState* pY,
   //                           IppsBigNumState* pZ,
   //                           const IppsECCPPointState* pPoint,
   //                           const IppsECCPState* pECC);
   void (*GetPointAffine)(IppsBigNumState* pX,
                          IppsBigNumState* pY,
                          const IppsECCPPointState* pPoint,
                          const IppsECCPState* pECC,
                          BigNumNode* pList);

   //void (*SetPointToInfinity)(IppsECCPPointState* pPoint);
   //void (*SetPointToAffineInfinity0)(IppsBigNumState* pX, IppsBigNumState* pY);
   //void (*SetPointToAffineInfinity1)(IppsBigNumState* pX, IppsBigNumState* pY);

   //int (*IsPointAtInfinity)(const IppsECCPPointState* pPoint);
   //int (*IsPointAtAffineInfinity0)(const IppsBigNumState* pX, const IppsBigNumState* pY);
   //int (*IsPointAtAffineInfinity1)(const IppsBigNumState* pX, const IppsBigNumState* pY);
   int (*IsPointOnCurve)(const IppsECCPPointState* pPoint,
                         const IppsECCPState* pECC,
                         BigNumNode* pList);

   int (*ComparePoint)(const IppsECCPPointState* pP,
                       const IppsECCPPointState* pQ,
                       const IppsECCPState* pECC,
                       BigNumNode* pList);
   void (*NegPoint)(const IppsECCPPointState* pP,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC);
   void (*DblPoint)(const IppsECCPPointState* pP,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList);
   void (*AddPoint)(const IppsECCPPointState* pP,
                    const IppsECCPPointState* pQ,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList);
   void (*MulPoint)(const IppsECCPPointState* pP,
                    const IppsBigNumState* pK,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList);
   void (*MulBasePoint)(const IppsBigNumState* pK,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList);
   void (*ProdPoint)(const IppsECCPPointState* pP,
                     const IppsBigNumState*    bnPscalar,
                     const IppsECCPPointState* pQ,
                     const IppsBigNumState*    bnQscalar,
                     IppsECCPPointState* pR,
                     const IppsECCPState* pECC,
                     BigNumNode* pList);
};
