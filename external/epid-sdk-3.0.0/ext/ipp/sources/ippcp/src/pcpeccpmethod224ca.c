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
//     EC methods over GF(P224)
// 
//  Contents:
//     ECCP224_SetPointProjective()
//     ECCP224_SetPointAffine()
//     ECCP224_GetPointAffine()
// 
//     ECCP224_IsPointOnCurve()
// 
//     ECCP224_ComparePoint()
//     ECCP224_NegPoint()
//     ECCP224_DblPoint()
//     ECCP224_AddPoint()
//     ECCP224_MulPoint()
//     ECCP224_ProdPoint()
// 
// 
*/

#include "precomp.h"
#include "owncp.h"

#if (_ECP_224_==_ECP_IMPL_SPECIFIC_)
#include "pcpeccppoint.h"
#include "pcpeccpmethod.h"
#include "pcpeccpmethodcom.h"
#include "pcpeccpmethod224.h"
#include "pcppma224.h"

/*
   NOTE:
   ECCP224 methods are used representation of point coordinates
   in regular (usual residue) domain, because of special modular reduction
*/
static
ECCP_METHOD ECCP224 = {
   ECCP224_SetPointProjective,
   ECCP224_SetPointAffine,
   ECCP224_GetPointAffine,

   ECCP224_IsPointOnCurve,

   ECCP224_ComparePoint,
   ECCP224_NegPoint,
   ECCP224_DblPoint,
   ECCP224_AddPoint,
   ECCP224_MulPoint,
   ECCP224_MulBasePoint,
   ECCP224_ProdPoint
};


/*
// Returns reference
*/
ECCP_METHOD* ECCP224_Methods(void)
{
   return &ECCP224;
}

/*
// ECCP224_PoinSettProjective
// Converts regular projective triplet (pX,pY,pZ) into pPoint
// (see note above)
*/
void ECCP224_SetPointProjective(const IppsBigNumState* pX,
                             const IppsBigNumState* pY,
                             const IppsBigNumState* pZ,
                             IppsECCPPointState* pPoint,
                             const IppsECCPState* pECC)
{
   UNREFERENCED_PARAMETER(pECC);
   cpBN_copy(ECP_POINT_X(pPoint), pX);
   cpBN_copy(ECP_POINT_Y(pPoint), pY);
   cpBN_copy(ECP_POINT_Z(pPoint), pZ);
   ECP_POINT_AFFINE(pPoint) = cpBN_cmp(pZ, BN_ONE_REF())==0;
}

/*
// ECCP224_PointAffineSet
// Converts regular affine pair (pX,pY) into pPoint
*/
void ECCP224_SetPointAffine(const IppsBigNumState* pX,
                         const IppsBigNumState* pY,
                         IppsECCPPointState* pPoint,
                         const IppsECCPState* pECC)
{
   ECCP224_SetPointProjective(pX, pY, BN_ONE_REF(), pPoint, pECC);
}

/*
// ECCP224_GetPointProjective
// Converts pPoint into regular projective triplet (pX,pY,pZ)
*/
#if 0
void ECCP224_GetPointProjective(IppsBigNumState* pX,
                             IppsBigNumState* pY,
                             IppsBigNumState* pZ,
                             const IppsECCPPointState* pPoint,
                             const IppsECCPState* pECC)
{
   UNREFERENCED_PARAMETER(pECC);
   cpBN_copy(pX, ECP_POINT_X(pPoint));
   cpBN_copy(pY, ECP_POINT_Y(pPoint));
   cpBN_copy(pZ, ECP_POINT_Z(pPoint));
}
#endif

/*
// ECCP224_GetPointAffine
//
// Converts pPoint into regular affine pair (pX,pY)
//
// Note:
// pPoint is not point at Infinity
// transform  (X, Y, Z)  into  (x, y) = (X/Z^2, Y/Z^3)
*/
void ECCP224_GetPointAffine(IppsBigNumState* pX, IppsBigNumState* pY,
                         const IppsECCPPointState* pPoint,
                         const IppsECCPState* pECC,
                         BigNumNode* pList)
{
   /* case Z == 1 */
   if( ECP_POINT_AFFINE(pPoint) ) {
      if(pX) {
         cpBN_copy(pX, ECP_POINT_X(pPoint));
      }
      if(pY) {
         cpBN_copy(pY, ECP_POINT_Y(pPoint));
      }
   }

   /* case Z != 1 */
   else {
      //IppsMontState* pMont = ECP_PMONT(pECC);
      IppsBigNumState* pModulo = ECP_PRIME(pECC);

      IppsBigNumState* pT = cpBigNumListGet(&pList);
      IppsBigNumState* pU = cpBigNumListGet(&pList);
      //IppsBigNumState* pModulo = cpBigNumListGet(&pList);
      //BN_Set(MNT_MODULUS(pMont), MNT_SIZE(pMont), pModulo);

      /* U = 1/Z */
      PMA224_inv(pU, ECP_POINT_Z(pPoint), pModulo);
      /* T = 1/(Z^2) */
      PMA224_sqr(pT, pU);

      if(pX) {
         PMA224_mul(pX,pT, ECP_POINT_X(pPoint));
      }
      if(pY) {
         /* U = 1/(Z^3) */
         PMA224_mul(pU, pU, pT);
         PMA224_mul(pY,pU, ECP_POINT_Y(pPoint));
      }
   }
}

/*
// ECCP224_IsPointOnCurve
//
// Test point is lie on curve
//
// Note
// We deal with equation: y^2 = x^3 + A*x + B.
// Or in projective coordinates: Y^2 = X^3 + a*X*Z^4 + b*Z^6.
// The point under test is given by projective triplet (X,Y,Z),
// which represents actually (x,y) = (X/Z^2,Y/Z^3).
*/
int ECCP224_IsPointOnCurve(const IppsECCPPointState* pPoint,
                        const IppsECCPState* pECC,
                        BigNumNode* pList)
{
   /* let think Infinity point is on the curve */
   if( ECCP_IsPointAtInfinity(pPoint) )
      return 1;

   else {
      IppsBigNumState* pR = cpBigNumListGet(&pList);
      IppsBigNumState* pT = cpBigNumListGet(&pList);

      PMA224_sqr(pR, ECP_POINT_X(pPoint));      // R = X^3
      PMA224_mul(pR, pR, ECP_POINT_X(pPoint));

      /* case Z != 1 */
      if( !ECP_POINT_AFFINE(pPoint) ) {
         IppsBigNumState* pZ4 = cpBigNumListGet(&pList);
         IppsBigNumState* pZ6 = cpBigNumListGet(&pList);
         PMA224_sqr(pT,  ECP_POINT_Z(pPoint));    // Z^2
         PMA224_sqr(pZ4, pT);                     // Z^4
         PMA224_mul(pZ6, pZ4, pT);                // Z^6

         PMA224_mul(pT, pZ4, ECP_POINT_X(pPoint)); // T = X*Z^4
         if( ECP_AMI3(pECC) ) {
            IppsBigNumState* pU = cpBigNumListGet(&pList);
               PMA224_add(pU, pT, pT);               // R = X^3 +a*X*Z^4
               PMA224_add(pU, pU, pT);
               PMA224_sub(pR, pR, pU);
         }
         else {
            PMA224_mul(pT, pT, ECP_A(pECC));     // R = X^3 +a*X*Z^4
            PMA224_add(pR, pR, pT);
         }
           PMA224_mul(pT, pZ6, ECP_B(pECC));       // R = X^3 +a*X*Z^4 + b*Z^6
           PMA224_add(pR, pR, pT);

      }
      /* case Z == 1 */
      else {
         if( ECP_AMI3(pECC) ) {
               PMA224_add(pT, ECP_POINT_X(pPoint), ECP_POINT_X(pPoint)); // R = X^3 +a*X
               PMA224_add(pT, pT, ECP_POINT_X(pPoint));
               PMA224_sub(pR, pR, pT);
         }
         else {
               PMA224_mul(pT, ECP_POINT_X(pPoint), ECP_A(pECC));       // R = X^3 +a*X
               PMA224_add(pR, pR, pT);
         }
         PMA224_add(pR, pR, ECP_B(pECC));                   // R = X^3 +a*X + b
      }
      PMA224_sqr(pT, ECP_POINT_Y(pPoint));  // T = Y^2
      return 0==cpBN_cmp(pR, pT);
   }
}

/*
// ECCP224_ComparePoint
//
// Compare two points:
//    returns 0 => pP==pQ (maybe both pP and pQ are at Infinity)
//    returns 1 => pP!=pQ
//
// Note
// In general we check:
//    P_X*Q_Z^2 ~ Q_X*P_Z^2
//    P_Y*Q_Z^3 ~ Q_Y*P_Z^3
*/
int ECCP224_ComparePoint(const IppsECCPPointState* pP,
                      const IppsECCPPointState* pQ,
                      const IppsECCPState* pECC,
                      BigNumNode* pList)
{
   UNREFERENCED_PARAMETER(pECC);

   /* P or/and Q at Infinity */
   if( ECCP_IsPointAtInfinity(pP) )
      return ECCP_IsPointAtInfinity(pQ)? 0:1;
   if( ECCP_IsPointAtInfinity(pQ) )
      return ECCP_IsPointAtInfinity(pP)? 0:1;

   /* (P_Z==1) && (Q_Z==1) */
    if( ECP_POINT_AFFINE(pP) && ECP_POINT_AFFINE(pQ) )
      return ((0==cpBN_cmp(ECP_POINT_X(pP),ECP_POINT_X(pQ))) && (0==cpBN_cmp(ECP_POINT_Y(pP),ECP_POINT_Y(pQ))))? 0:1;

   {
      IppsBigNumState* pPtmp = cpBigNumListGet(&pList);
      IppsBigNumState* pQtmp = cpBigNumListGet(&pList);
      IppsBigNumState* pPZ   = cpBigNumListGet(&pList);
      IppsBigNumState* pQZ   = cpBigNumListGet(&pList);

      /* P_X*Q_Z^2 ~ Q_X*P_Z^2 */
      if( !ECP_POINT_AFFINE(pQ) ) {
         PMA224_sqr(pQZ, ECP_POINT_Z(pQ));      /* Ptmp = P_X*Q_Z^2 */
         PMA224_mul(pPtmp, ECP_POINT_X(pP), pQZ);
      }
      else {
         PMA_set(pPtmp, ECP_POINT_X(pP));
      }
      if( !ECP_POINT_AFFINE(pP) ) {
         PMA224_sqr(pPZ, ECP_POINT_Z(pP));      /* Qtmp = Q_X*P_Z^2 */
         PMA224_mul(pQtmp, ECP_POINT_X(pQ), pPZ);
      }
      else {
         PMA_set(pQtmp, ECP_POINT_X(pQ));
      }
      if ( cpBN_cmp(pPtmp, pQtmp) )
         return 1;   /* points are different: (P_X*Q_Z^2) != (Q_X*P_Z^2) */

      /* P_Y*Q_Z^3 ~ Q_Y*P_Z^3 */
      if( !ECP_POINT_AFFINE(pQ) ) {
         PMA224_mul(pQZ, pQZ, ECP_POINT_Z(pQ)); /* Ptmp = P_Y*Q_Z^3 */
         PMA224_mul(pPtmp, ECP_POINT_Y(pP), pQZ);
      }
      else {
         PMA_set(pPtmp, ECP_POINT_Y(pP));
      }
      if( !ECP_POINT_AFFINE(pP) ) {
         PMA224_mul(pPZ, pPZ, ECP_POINT_Z(pP)); /* Qtmp = Q_Y*P_Z^3 */
         PMA224_mul(pQtmp, ECP_POINT_Y(pQ), pPZ);
      }
      else {
         PMA_set(pQtmp, ECP_POINT_Y(pQ));
      }
      return cpBN_cmp(pPtmp, pQtmp)? 1:0;
   }
}

/*
// ECCP224_NegPoint
//
// Negative point
*/
void ECCP224_NegPoint(const IppsECCPPointState* pP,
                   IppsECCPPointState* pR,
                   const IppsECCPState* pECC)
{
   UNREFERENCED_PARAMETER(pECC);

   /* test point at Infinity */
   if( ECCP_IsPointAtInfinity(pP) )
      ECCP_SetPointToInfinity(pR);

   else {
      BNU_CHUNK_T* pRy = BN_NUMBER(ECP_POINT_Y(pR));
      BNU_CHUNK_T* pPy = BN_NUMBER(ECP_POINT_Y(pP));
      int size = LEN_P224;

      if( pP!=pR ) {
         PMA_set(ECP_POINT_X(pR), ECP_POINT_X(pP));
         PMA_set(ECP_POINT_Z(pR), ECP_POINT_Z(pP));
         ECP_POINT_AFFINE(pR) = ECP_POINT_AFFINE(pP);
      }
      cpSub_BNU(pRy, (BNU_CHUNK_T*)secp224r1_p, pPy, LEN_P224);
      FIX_BNU(pRy,size);
      BN_SIZE(ECP_POINT_Y(pR)) = size;
      BN_SIGN(ECP_POINT_Y(pR)) = ippBigNumPOS;
   }
}

/*
// ECCP224_DblPoint
//
// Double point
*/
void ECCP224_DblPoint(const IppsECCPPointState* pP,
                   IppsECCPPointState* pR,
                   const IppsECCPState* pECC,
                   BigNumNode* pList)
{
   /* P at infinity */
   if( ECCP_IsPointAtInfinity(pP) )
      ECCP_SetPointToInfinity(pR);

   else {
      IppsBigNumState* bnV = cpBigNumListGet(&pList);
      IppsBigNumState* bnU = cpBigNumListGet(&pList);
      IppsBigNumState* bnM = cpBigNumListGet(&pList);
      IppsBigNumState* bnS = cpBigNumListGet(&pList);
      IppsBigNumState* bnT = cpBigNumListGet(&pList);

      /* M = 3*X^2 + A*Z^4 */
       if( ECP_POINT_AFFINE(pP) ) {
           PMA224_sqr(bnU, ECP_POINT_X(pP));
           PMA224_add(bnM, bnU, bnU);
           PMA224_add(bnM, bnM, bnU);
           PMA224_add(bnM, bnM, ECP_A(pECC));
        }
       else if( ECP_AMI3(pECC) ) {
           PMA224_sqr(bnU, ECP_POINT_Z(pP));
           PMA224_add(bnS, ECP_POINT_X(pP), bnU);
           PMA224_sub(bnT, ECP_POINT_X(pP), bnU);
           PMA224_mul(bnM, bnS, bnT);
           PMA224_add(bnU, bnM, bnM);
           PMA224_add(bnM, bnU, bnM);
        }
       else {
           PMA224_sqr(bnU, ECP_POINT_X(pP));
           PMA224_add(bnM, bnU, bnU);
           PMA224_add(bnM, bnM, bnU);
           PMA224_sqr(bnU, ECP_POINT_Z(pP));
           PMA224_sqr(bnU, bnU);
           PMA224_mul(bnU, bnU, ECP_A(pECC));
           PMA224_add(bnM, bnM, bnU);
        }

      PMA224_add(bnV, ECP_POINT_Y(pP), ECP_POINT_Y(pP));

      /* R_Z = 2*Y*Z */
      if( ECP_POINT_AFFINE(pP) ) {
         PMA_set(ECP_POINT_Z(pR), bnV);
      }
      else {
         PMA224_mul(ECP_POINT_Z(pR), bnV, ECP_POINT_Z(pP));
      }

      /* S = 4*X*Y^2 */
      PMA224_sqr(bnT, bnV);
      PMA224_mul(bnS, bnT, ECP_POINT_X(pP));

      /* R_X = M^2 - 2*S */
      PMA224_sqr(bnU, bnM);
      PMA224_sub(bnU, bnU, bnS);
      PMA224_sub(ECP_POINT_X(pR), bnU, bnS);

      /* T = 8*Y^4 */
      PMA224_mul(bnV, bnV, ECP_POINT_Y(pP));
      PMA224_mul(bnT, bnT, bnV);

      /* R_Y = M*(S - R_X) - T */
      PMA224_sub(bnS, bnS, ECP_POINT_X(pR));
      PMA224_mul(bnS, bnS, bnM);
      PMA224_sub(ECP_POINT_Y(pR), bnS, bnT);

      ECP_POINT_AFFINE(pR) = 0;
   }
}

/*
// ECCP224_AddPoint
//
// Add points
*/
void ECCP224_AddPoint(const IppsECCPPointState* pP,
                   const IppsECCPPointState* pQ,
                   IppsECCPPointState* pR,
                   const IppsECCPState* pECC,
                   BigNumNode* pList)
{
#if 0
   /* test stupid call */
   if( pP == pQ ) {
      ECCP224_DblPoint(pP, pR, pECC, pList);
      return;
   }
#endif

   /* prevent operation with point at Infinity */
   if( ECCP_IsPointAtInfinity(pP) ) {
      ECCP_CopyPoint(pQ, pR);
      return;
   }
   if( ECCP_IsPointAtInfinity(pQ) ) {
      ECCP_CopyPoint(pP, pR);
      return;
   }

   /*
   // addition
   */
   {
      IppsBigNumState* bnU0 = cpBigNumListGet(&pList);
      IppsBigNumState* bnS0 = cpBigNumListGet(&pList);
      IppsBigNumState* bnU1 = cpBigNumListGet(&pList);
      IppsBigNumState* bnS1 = cpBigNumListGet(&pList);
      IppsBigNumState* bnW  = cpBigNumListGet(&pList);
      IppsBigNumState* bnR  = cpBigNumListGet(&pList);
      IppsBigNumState *bnT  = bnU0;
      IppsBigNumState *bnM  = bnS0;

      /* U0 = P_X * Q_Z^2 */
      /* S0 = P_Y * Q_Z^3 */
      if( ECP_POINT_AFFINE(pQ) ) {
         PMA_set(bnU0, ECP_POINT_X(pP));
         PMA_set(bnS0, ECP_POINT_Y(pP));
      }
      else {
         PMA224_sqr(bnW, ECP_POINT_Z(pQ));
         PMA224_mul(bnU0,ECP_POINT_X(pP), bnW);
         PMA224_mul(bnW, ECP_POINT_Z(pQ), bnW);
         PMA224_mul(bnS0,ECP_POINT_Y(pP), bnW);
      }

      /* U1 = Q_X * P_Z^2 */
      /* S1 = Q_Y * P_Z^3 */
      if( ECP_POINT_AFFINE(pP) ) {
         PMA_set(bnU1, ECP_POINT_X(pQ));
         PMA_set(bnS1, ECP_POINT_Y(pQ));
      }
      else {
         PMA224_sqr(bnW, ECP_POINT_Z(pP));
         PMA224_mul(bnU1,ECP_POINT_X(pQ), bnW);
         PMA224_mul(bnW, ECP_POINT_Z(pP), bnW);
         PMA224_mul(bnS1,ECP_POINT_Y(pQ), bnW);
      }

      /* W = U0-U1 */
      /* R = S0-S1 */
      PMA224_sub(bnW, bnU0, bnU1);
      PMA224_sub(bnR, bnS0, bnS1);

      //if( IsZero_BN(bnW) ) {
         //if( IsZero_BN(bnR) ) {
      if(cpEqu_BNU_CHUNK(BN_NUMBER(bnW), LEN_P224, 0)) {
         if(cpEqu_BNU_CHUNK(BN_NUMBER(bnR), LEN_P224, 0)) {
            ECCP224_DblPoint(pP, pR, pECC, pList);
            return;
         }
         else {
            ECCP_SetPointToInfinity(pR);
            return;
         }
      }

      /* T = U0+U1 */
      /* M = S0+S1 */
      PMA224_add(bnT, bnU0, bnU1);
      PMA224_add(bnM, bnS0, bnS1);

      /* R_Z = P_Z * Q_Z * W */
      if( ECP_POINT_AFFINE(pQ) && ECP_POINT_AFFINE(pP) ) {
         PMA_set(ECP_POINT_Z(pR), bnW);
      }
      else {
         if( ECP_POINT_AFFINE(pQ) ) {
            PMA_set(bnU1, ECP_POINT_Z(pP));
         }
         else if( ECP_POINT_AFFINE(pP) ) {
            PMA_set(bnU1, ECP_POINT_Z(pQ));
         }
         else {
            PMA224_mul(bnU1, ECP_POINT_Z(pP), ECP_POINT_Z(pQ));
         }
         PMA224_mul(ECP_POINT_Z(pR), bnU1, bnW);
      }

      PMA224_sqr(bnU1, bnW);         /* U1 = W^2     */
      PMA224_mul(bnS1, bnT, bnU1);   /* S1 = T * W^2 */

      /* R_X = R^2 - T * W^2 */
      PMA224_sqr(ECP_POINT_X(pR), bnR);
      PMA224_sub(ECP_POINT_X(pR), ECP_POINT_X(pR), bnS1);

      /* V = T * W^2 - 2 * R_X  (S1) */
      PMA224_sub(bnS1, bnS1, ECP_POINT_X(pR));
      PMA224_sub(bnS1, bnS1, ECP_POINT_X(pR));

      /* R_Y = (V * R - M * W^3) /2 */
      PMA224_mul(ECP_POINT_Y(pR), bnS1, bnR);
      PMA224_mul(bnU1, bnU1, bnW);
      PMA224_mul(bnU1, bnU1, bnM);
      PMA224_sub(bnU1, ECP_POINT_Y(pR), bnU1);
      PMA224_div2(ECP_POINT_Y(pR), bnU1);

      ECP_POINT_AFFINE(pR) = 0;
   }
}

/*
// ECCP224_MulPoint
//
// Multiply point by scalar
*/
#if !defined (_USE_ECCP_SSCM_)
void ECCP224_MulPoint(const IppsECCPPointState* pP,
                   const IppsBigNumState* bnN,
                   IppsECCPPointState* pR,
                   const IppsECCPState* pECC,
                   BigNumNode* pList)
{
   /* test zero scalar or input point at Infinity */
   if( IsZero_BN(bnN) || ECCP_IsPointAtInfinity(pP) ) {
      ECCP_SetPointToInfinity(pR);
      return;
   }

   /*
   // scalar multiplication
   */
   else {
      IppsECCPPointState T;
      IppsECCPPointState U;
      IppsBigNumState* bnKH = cpBigNumListGet(&pList);
      Ipp32u* pK;
      Ipp32u* pH;
      Ipp32u carry;
      int lenKH;
      int bitH;

      /* init result */
      ECCP_CopyPoint(pP, pR);

      /* if scalar is negative */
      if( ippBigNumNEG == BN_SIGN(bnN) ) {
         /* negative R */
         ECCP224_NegPoint(pR, pR, pECC);
      }

      /* copy K = N and compute H=3*K */
      lenKH = BN_SIZE(bnN)+1;
      pK = BN_NUMBER(bnKH);
      pH = BN_BUFFER(bnKH);
      Cpy_BNU(BN_NUMBER(bnN), pK, BN_SIZE(bnN));
      pK[lenKH-1] = 0;
      carry = cpAdd_BNU(pH, pK, pK, lenKH);
      carry = cpAdd_BNU(pH, pK, pH, lenKH);

      /* init temporary T = (X/Z^2, Y/Z^3, 1) */
      ECP_POINT_X(&T) = cpBigNumListGet(&pList);
      ECP_POINT_Y(&T) = cpBigNumListGet(&pList);
      ECP_POINT_Z(&T) = cpBigNumListGet(&pList);
      ECCP224_GetPointAffine(ECP_POINT_X(&T), ECP_POINT_Y(&T), pR, pECC, pList);
      ECCP224_SetPointAffine(ECP_POINT_X(&T), ECP_POINT_Y(&T), &T, pECC);

      /* temporary point U =-T */
      ECP_POINT_X(&U) = cpBigNumListGet(&pList);
      ECP_POINT_Y(&U) = cpBigNumListGet(&pList);
      ECP_POINT_Z(&U) = cpBigNumListGet(&pList);
      ECCP224_NegPoint(&T, &U, pECC);

      for(bitH=MSB_BNU(pH, lenKH)-1; bitH>0; bitH--) {
         int hBit = TST_BIT(pH, bitH);
         int kBit = TST_BIT(pK, bitH);
         ECCP224_DblPoint(pR, pR, pECC, pList);
         if( hBit && !kBit )
            ECCP224_AddPoint(pR, &T, pR, pECC, pList);
         if(!hBit &&  kBit )
            ECCP224_AddPoint(pR, &U, pR, pECC, pList);
      }
   }
}

#else
#pragma message ("ECCP224_MulPoint: SCCM version")

void ECCP224_MulPoint(const IppsECCPPointState* pP,
                   const IppsBigNumState* bnN,
                   IppsECCPPointState* pR,
                   const IppsECCPState* pECC,
                   BigNumNode* pList)
{
   /* test zero scalar or input point at Infinity */
   if( IsZero_BN(bnN) || ECCP_IsPointAtInfinity(pP) ) {
      ECCP_SetPointToInfinity(pR);
      return;
   }

   /*
   // scalar multiplication
   */
   else {
      Ipp8u* pScratchAligned = ECP_SCCMBUFF(pECC);

      BNU_CHUNK_T* pN = BN_NUMBER(bnN);
      cpSize nsN = BN_SIZE(bnN);
      /* scalar bitsize */
      int scalarBitSize = BITSIZE_BNU(pN, nsN);
      /* optimal size of window */
      int w = cpECCP_OptimalWinSize(scalarBitSize);
      /* number of table entries */
      int nPrecomputed = 1<<w;

      /* allocate temporary scalar */
      IppsBigNumState* bnTN = cpBigNumListGet(&pList);
      BNU_CHUNK_T* pTN = BN_NUMBER(bnTN);

      int coordSize = BITS_BNU_CHUNK(ECP_GFEBITS(pECC));
      IppsECCPPointState T;
      ECP_POINT_X(&T) = cpBigNumListGet(&pList);
      ECP_POINT_Y(&T) = cpBigNumListGet(&pList);
      ECP_POINT_Z(&T) = cpBigNumListGet(&pList);
      ECCP_SetPointToInfinity(&T);

      /* init result */
      ECCP_CopyPoint(pP, pR);
      if( ippBigNumNEG == BN_SIGN(bnN) )
         ECCP224_NegPoint(pR, pR, pECC);

      /* pre-compute auxiliary table t[] = {(2^w)*P, 1*P, 2*P, ..., (2^(w-1))*P} */
      {
         int n;
         for(n=1; n<nPrecomputed; n++) {
            ECCP224_AddPoint(pR, &T, &T, pECC, pList);
            cpECCP_ScramblePut(pScratchAligned+n, nPrecomputed, &T, coordSize);
         }
         ECCP224_AddPoint(pR, &T, &T, pECC, pList);
         cpECCP_ScramblePut(pScratchAligned, nPrecomputed, &T, coordSize);
      }

      /* copy scalar */
      cpCpy_BNU(pTN, pN, nsN);
      /* and convert it presentaion to avoid usage of O point */
      scalarBitSize = cpECCP_ConvertRepresentation(pTN, scalarBitSize, w);

      /* prepare temporary scalar for processing */
      pTN[BITS_BNU_CHUNK(scalarBitSize)] = 0;
      scalarBitSize = ((scalarBitSize+w-1)/w)*w;

      /*
      // scalar multiplication
      */
      {
         Ipp32u dmask = nPrecomputed-1;

         /* position (bit number) of the leftmost window */
         int wPosition = scalarBitSize-w;

         /* extract leftmost window value */
         Ipp32u eChunk = *((Ipp32u*)((Ipp16u*)pTN + wPosition/BITSIZE(Ipp16u)));
         int shift = wPosition & 0xF;
         Ipp32u windowVal = (eChunk>>shift) & dmask;

         /* initialize result (ECP_FINITE_POINT|ECP_PROJECTIVE) */
         cpECCP_ScrambleGet(pR, coordSize, pScratchAligned+windowVal, nPrecomputed);
         ECP_POINT_AFFINE(pR) = 0;

         /* initialize temporary T (ECP_PROJECTIVE) */
         ECP_POINT_AFFINE(&T) = 0;

         for(wPosition-=w; wPosition>=0; wPosition-=w) {
            /* w times doubling */
            int k;
            for(k=0; k<w; k++)
               ECCP224_DblPoint(pR, pR, pECC, pList);

            /* extract next window value */
            eChunk = *((Ipp32u*)((Ipp16u*)pTN + wPosition/BITSIZE(Ipp16u)));
            shift = wPosition & 0xF;
            windowVal = (eChunk>>shift) & dmask;

            /* extract value from the pre-computed table */
            cpECCP_ScrambleGet(&T, coordSize, pScratchAligned+windowVal, nPrecomputed);

            /* and add it */
            ECCP224_AddPoint(pR, &T, pR, pECC, pList);
         }
      }
   }
}
#endif

void ECCP224_MulBasePoint(const IppsBigNumState* pK,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList)
{
   ECCP224_MulPoint(ECP_GENC(pECC), pK, pR, pECC, pList);
}

/*
// ECCP224_ProdPoint
//
// Point product
*/
#if !defined (_USE_ECCP_SSCM_)
void ECCP224_ProdPoint(const IppsECCPPointState* pP,
                    const IppsBigNumState*    bnPscalar,
                    const IppsECCPPointState* pQ,
                    const IppsBigNumState*    bnQscalar,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList)
{
   /* test zero scalars */
   if( IsZero_BN(bnPscalar) ) {
      ECCP224_MulPoint(pQ, bnQscalar, pR, pECC, pList);
      return;
   }
   if( IsZero_BN(bnQscalar) ) {
      ECCP224_MulPoint(pP, bnPscalar, pR, pECC, pList);
      return;
   }

   /*
   // point product
   */
   else {
      int n;
      Ipp32u* pbnPscalar = BN_NUMBER(bnPscalar);
      int bnPscalarSize  = BN_SIZE(bnPscalar);
      Ipp32u* pbnQscalar = BN_NUMBER(bnQscalar);
      int bnQscalarSize  = BN_SIZE(bnQscalar);

      int size = bnPscalarSize>bnQscalarSize? bnPscalarSize : bnQscalarSize;

      IppsECCPPointState* pPointPQ[4] = {NULL, NULL, NULL, NULL};

      /* allocate temporary PQ point */
      IppsECCPPointState PQ;
      ECP_POINT_X(&PQ) = cpBigNumListGet(&pList);
      ECP_POINT_Y(&PQ) = cpBigNumListGet(&pList);
      ECP_POINT_Z(&PQ) = cpBigNumListGet(&pList);

      /* init temporary point array */
      if(ippBigNumPOS == BN_SIGN(bnPscalar))
         pPointPQ[1] = (IppsECCPPointState*)pP;
      else {
         IppsECCPPointState P;
         ECP_POINT_X(&P) = cpBigNumListGet(&pList);
         ECP_POINT_Y(&P) = cpBigNumListGet(&pList);
         ECP_POINT_Z(&P) = cpBigNumListGet(&pList);
         ECCP224_NegPoint(pP, &P, pECC);
         pPointPQ[1] = &P;
      }
      if(ippBigNumPOS == BN_SIGN(bnQscalar))
         pPointPQ[2] = (IppsECCPPointState*)pQ;
      else {
         IppsECCPPointState Q;
         ECP_POINT_X(&Q) = cpBigNumListGet(&pList);
         ECP_POINT_Y(&Q) = cpBigNumListGet(&pList);
         ECP_POINT_Z(&Q) = cpBigNumListGet(&pList);
         ECCP224_NegPoint(pQ, &Q, pECC);
         pPointPQ[2] = &Q;
      }

      ECCP224_AddPoint(pPointPQ[1], pPointPQ[2], &PQ, pECC, pList);
      ECCP224_GetPointAffine(ECP_POINT_X(pR), ECP_POINT_Y(pR), &PQ, pECC, pList);
      ECCP224_SetPointAffine(ECP_POINT_X(pR), ECP_POINT_Y(pR), &PQ, pECC);
      pPointPQ[3] = &PQ;

      /* pad scalars by zeros */
      ZEXPAND_BNU(pbnPscalar,bnPscalarSize, size);
      ZEXPAND_BNU(pbnQscalar,bnQscalarSize, size);

      /* init result */
      ECCP_SetPointToInfinity(pR);

      for(n=size; n>0; n--) {
         Ipp32u scalarPn = pbnPscalar[n-1];
         Ipp32u scalarQn = pbnQscalar[n-1];

         int nBit;
         for(nBit=31; nBit>=0; nBit--) {
            int
            PnQnBits = scalarPn&0x80000000? 1:0;
            PnQnBits+= scalarQn&0x80000000? 2:0;

            if( !ECCP_IsPointAtInfinity(pR) )
               ECCP224_DblPoint(pR, pR, pECC, pList);
            if( PnQnBits )
               ECCP224_AddPoint(pR, pPointPQ[PnQnBits], pR, pECC, pList);

            scalarPn <<= 1;
            scalarQn <<= 1;
         }
      }
   }
}

#else
#pragma message ("ECCP224_ProdPoint: SCCM version")

void ECCP224_ProdPoint(const IppsECCPPointState* pP,
                    const IppsBigNumState*    bnPscalar,
                    const IppsECCPPointState* pQ,
                    const IppsBigNumState*    bnQscalar,
                    IppsECCPPointState* pR,
                    const IppsECCPState* pECC,
                    BigNumNode* pList)
{
   IppsECCPPointState T;
   IppsECCPPointState U;

   ECP_POINT_X(&T) = cpBigNumListGet(&pList);
   ECP_POINT_Y(&T) = cpBigNumListGet(&pList);
   ECP_POINT_Z(&T) = cpBigNumListGet(&pList);

   ECP_POINT_X(&U) = cpBigNumListGet(&pList);
   ECP_POINT_Y(&U) = cpBigNumListGet(&pList);
   ECP_POINT_Z(&U) = cpBigNumListGet(&pList);

   ECCP224_MulPoint(pP, bnPscalar, &T, (IppsECCPState*)pECC, pList);
   ECCP224_MulPoint(pQ, bnQscalar, &U, (IppsECCPState*)pECC, pList);
   ECCP224_AddPoint(&T, &U, pR, pECC, pList);
}
#endif

#endif /* _ECP_224_==_ECP_IMPL_SPECIFIC_ */
